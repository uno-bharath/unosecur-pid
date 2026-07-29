import type { Metadata } from 'next';
import './styles.css';

export const metadata: Metadata = {
  title: 'UnoSecur Identity Copilot',
  description: 'Explainable toxic identity intelligence',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
