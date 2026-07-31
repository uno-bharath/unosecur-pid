import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  KubeConfig,
  RbacAuthorizationV1Api,
  V1PolicyRule,
  V1RoleRef,
  RbacV1Subject,
} from '@kubernetes/client-node';
import { EffectiveGrant, IdentityAccessSnapshot } from '../domain/toxic-access.types';
import { IdentityAccessSource } from '../ports/identity-access-source';

const PRODUCTION_CONTEXT = /(^|[-_/])(prod|production)([-_/]|$)/i;
const NON_PRODUCTION_CONTEXT = /(^|[-_/])(non[-_]?prod|nonproduction)([-_/]|$)/i;

@Injectable()
export class KubernetesIdentityAccessSource extends IdentityAccessSource {
  readonly sourceName = 'kubernetes-kubeconfig';
  private readonly logger = new Logger(KubernetesIdentityAccessSource.name);

  constructor(private readonly config: ConfigService) {
    super();
  }

  async getIdentity(identityId: string): Promise<IdentityAccessSnapshot | null> {
    return (await this.listIdentities()).find((identity) => identity.identityId === identityId) ?? null;
  }

  async listIdentities(): Promise<IdentityAccessSnapshot[]> {
    const contexts = this.selectedContexts();
    const results = await Promise.allSettled(
      contexts.map((context) =>
        Promise.race([
          this.scanContext(context),
          new Promise<IdentityAccessSnapshot[]>((_, reject) =>
            setTimeout(() => reject(new Error('RBAC discovery timed out after 15 seconds')), 15_000),
          ),
        ]),
      ),
    );
    return results.flatMap((result, index) => {
      if (result.status === 'fulfilled') return result.value;
      this.logger.warn(`Skipping Kubernetes context ${contexts[index]}: ${result.reason instanceof Error ? result.reason.message : 'connection failed'}`);
      return [];
    });
  }

  private selectedContexts(): string[] {
    const kubeConfig = this.loadConfig();
    const configured = this.csv('KUBERNETES_CONTEXTS');
    const discover = this.config.get<boolean>('KUBERNETES_CONTEXT_DISCOVERY') ?? true;
    const allowProduction = this.config.get<boolean>('KUBERNETES_ALLOW_PRODUCTION') ?? false;
    const candidates = configured.length > 0
      ? configured
      : discover
        ? kubeConfig.getContexts().map(({ name }) => name)
        : [];
    return candidates.filter(
      (context) =>
        allowProduction ||
        !PRODUCTION_CONTEXT.test(context) ||
        NON_PRODUCTION_CONTEXT.test(context),
    );
  }

  private async scanContext(context: string): Promise<IdentityAccessSnapshot[]> {
    const kubeConfig = this.loadConfig();
    kubeConfig.setCurrentContext(context);
    const api = kubeConfig.makeApiClient(RbacAuthorizationV1Api);
    const [clusterRoles, clusterBindings, roles, roleBindings] = await Promise.all([
      api.listClusterRole(),
      api.listClusterRoleBinding(),
      api.listRoleForAllNamespaces(),
      api.listRoleBindingForAllNamespaces(),
    ]);
    const includedNamespaces = new Set(this.csv('KUBERNETES_INCLUDE_NAMESPACES'));
    const clusterRoleRules = new Map(
      clusterRoles.body.items.map((role) => [role.metadata?.name ?? '', role.rules ?? []]),
    );
    const roleRules = new Map(
      roles.body.items.map((role) => [`${role.metadata?.namespace ?? 'default'}/${role.metadata?.name ?? ''}`, role.rules ?? []]),
    );
    const snapshots = new Map<string, IdentityAccessSnapshot>();

    const addBinding = (
      subjects: RbacV1Subject[] | undefined,
      roleRef: V1RoleRef,
      namespace: string | undefined,
      rules: V1PolicyRule[],
    ) => {
      if (namespace && includedNamespaces.size > 0 && !includedNamespaces.has(namespace)) return;
      for (const subject of subjects ?? []) {
        const identityId = `k8s:${context}:${subject.kind}:${subject.namespace ?? ''}:${subject.name}`;
        const snapshot: IdentityAccessSnapshot = snapshots.get(identityId) ?? {
          identityId,
          displayName: subject.kind === 'ServiceAccount'
            ? `${subject.namespace ?? 'default'}/${subject.name}`
            : subject.name,
          type: subject.kind === 'ServiceAccount' ? 'SERVICE_ACCOUNT' : 'HUMAN',
          provider: 'Kubernetes',
          grants: [] as EffectiveGrant[],
        } satisfies IdentityAccessSnapshot;
        snapshot.grants.push(
          ...this.grantsForRole(context, namespace, subject, roleRef.name, rules),
        );
        snapshots.set(identityId, snapshot);
      }
    };

    for (const binding of clusterBindings.body.items) {
      addBinding(
        binding.subjects,
        binding.roleRef,
        undefined,
        clusterRoleRules.get(binding.roleRef.name) ?? [],
      );
    }
    for (const binding of roleBindings.body.items) {
      const namespace = binding.metadata?.namespace ?? 'default';
      const key = binding.roleRef.kind === 'ClusterRole'
        ? binding.roleRef.name
        : `${namespace}/${binding.roleRef.name}`;
      const rules = binding.roleRef.kind === 'ClusterRole'
        ? clusterRoleRules.get(key) ?? []
        : roleRules.get(key) ?? [];
      addBinding(binding.subjects, binding.roleRef, namespace, rules);
    }
    return [...snapshots.values()];
  }

  private grantsForRole(
    context: string,
    namespace: string | undefined,
    subject: RbacV1Subject,
    roleName: string,
    rules: V1PolicyRule[],
  ): EffectiveGrant[] {
    const resource = `k8s:${context}:${namespace ?? 'cluster'}`;
    const permissions = new Set<string>();
    if (roleName === 'cluster-admin') permissions.add('k8s:cluster-admin');
    for (const rule of rules) {
      const verbs = rule.verbs ?? [];
      const resources = rule.resources ?? [];
      if (verbs.includes('*') || resources.includes('*')) permissions.add('k8s:rbac:wildcard');
      if (verbs.includes('bind')) permissions.add('k8s:bind');
      if (verbs.includes('escalate')) permissions.add('k8s:escalate');
      if (resources.includes('secrets') && verbs.some((verb) => ['get', 'list', 'watch', '*'].includes(verb))) permissions.add('k8s:secrets:read');
      if (resources.includes('pods') && verbs.some((verb) => ['create', '*'].includes(verb))) permissions.add('k8s:pods:create');
      if (resources.includes('deployments') && verbs.some((verb) => ['create', '*'].includes(verb))) permissions.add('k8s:deployments:create');
    }
    if (permissions.has('k8s:cluster-admin') || permissions.has('k8s:rbac:wildcard')) {
      ['k8s:bind', 'k8s:escalate', 'k8s:secrets:read', 'k8s:pods:create', 'k8s:deployments:create'].forEach((permission) => permissions.add(permission));
    }
    return [...permissions].map((permission, index) => ({
      id: `k8s:${context}:${subject.kind}:${subject.name}:${roleName}:${index}`,
      platform: 'Kubernetes',
      permission,
      resource,
      assignment: {
        source: `${namespace ? 'RoleBinding' : 'ClusterRoleBinding'}:${roleName}`,
        path: [subject.name, roleName, permission, resource],
      },
    }));
  }

  private loadConfig(): KubeConfig {
    const kubeConfig = new KubeConfig();
    const path = this.config.get<string>('KUBERNETES_KUBECONFIG')?.trim();
    if (path) kubeConfig.loadFromFile(path);
    else kubeConfig.loadFromDefault();
    return kubeConfig;
  }

  private csv(key: string): string[] {
    return (this.config.get<string>(key) ?? '').split(',').map((value) => value.trim()).filter(Boolean);
  }
}
