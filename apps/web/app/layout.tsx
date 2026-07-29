import type { Metadata } from 'next';
import './styles.css';

export const metadata: Metadata = {
  title: 'UnoSecur Toxic Access Intelligence',
  description: 'Cross-platform entitlement conflict intelligence and remediation simulation',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
