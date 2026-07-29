import * as colors from './colors.js'
import { createDebug } from './debug.js'
import * as figures from './figures.js'

const debugLog = createDebug('lint-staged:runParallelTasks')

/** @param {Number | boolean} options.concurrent Boolean value for whether to run concurrently */
export const parseConcurrency = (concurrent) => {
  if (concurrent === true || concurrent === Infinity) {
    return Infinity
  }

  if (concurrent === false || concurrent < 1 || !Number.isInteger(concurrent)) {
    return 1
  }

  return concurrent
}

/**
 * @param {Object} ctx
 * @param {Array} tasks
 * @param {Object} options
 * @param {AbortController} abortController
 * @param {Number | boolean} [options.concurrent=true] Boolean value for whether to run concurrently,
 * or a number value controls the number of concurrent executions
 */
export const runParallelTasks = async (
  ctx,
  tasks,
  { abortController, concurrent = true, logger }
) => {
  const concurrency = parseConcurrency(concurrent)

  debugLog('Running parallel tasks with concurrency:', concurrency)

  const indent = tasks.length > 1 ? '    ' : '  '
  const allPerGlobTasks = []

  // the array of actual tasks is split per config and per glob
  for (const perConfig of tasks) {
    if (perConfig.skip()) {
      debugLog('Skipped configuration:', perConfig.title)
    } else {
      debugLog('Running configuration:', perConfig.title)

      if (tasks.length > 1) {
        // display name of config only when there are multiple
        logger?.log(colors.dim(`${indent}${perConfig.title}`))
      }
    }

    for (const perGlob of perConfig.task) {
      if (perGlob.skip()) {
        debugLog('Skipped glob from configuration:', perConfig.title, perGlob.title)
        continue
      }

      if (perConfig.skip()) {
        continue // entire group is skipped, but debug logs still show above
      }

      debugLog('Running glob:', perGlob.title)
      logger?.log(colors.dim(`${indent}  ${perGlob.title}`))

      for (const task of perGlob.task) {
        debugLog('Running task:', task.title)
        logger?.log(colors.dim(`${indent}    ${figures.wip()} ${task.title}`))
      }
      // per-glob tasks run serially
      allPerGlobTasks.push(perGlob.task)
    }
  }

  logger?.log('') // empty line before all tasks

  const runSequential = async (tasks) => {
    for (const { title, task } of tasks) {
      if (abortController.signal.aborted) {
        debugLog('Skipped task because aborted:', title)
        // Log all aborted tasks without actually running them
        logger?.warn(`${figures.cancelled()} ${title}`)
        continue
      }

      try {
        debugLog('Running task:', title)
        await task(ctx)
        debugLog('Done running task:', title)
        logger?.log(`${figures.done()} ${title}`)
      } catch {
        debugLog('Failed to run task:', title)
        logger?.error(colors.red(`${figures.error()} ${title}`))
      }
    }
  }

  let next = 0
  const worker = async () => {
    while (next < allPerGlobTasks.length) {
      const perGlobTasks = allPerGlobTasks[next++]
      await runSequential(perGlobTasks)
    }
  }

  const length = Math.min(allPerGlobTasks.length, concurrency)
  debugLog('Running workers with concurrency:', length)
  await Promise.all(Array.from({ length }, worker))
  debugLog('Done running workers')

  logger?.log('') // empty line after all tasks
}
