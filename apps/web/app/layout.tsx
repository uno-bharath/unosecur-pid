import type { Metadata } from 'next';
import './styles.css';

export const metadata: Metadata = {
  title: 'UnoSecur PID — Privilege Intelligence & Detection',
  description: 'Cross-platform entitlement conflict intelligence and remediation simulation',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
