import { Code2, Mail, Menu, Search, Shield, X } from 'lucide-react';
import React, { useState } from 'react';
import EmailAnalyzer from './components/EmailAnalyzer';
import URLScanner from './components/URLScanner';

type Tab = 'url' | 'email';

const NAV_ITEMS: { id: Tab; label: string; icon: React.ReactNode; desc: string }[] = [
  { id: 'url',   label: 'URL Scanner',   icon: <Search size={18} />, desc: 'Check links for threats' },
  { id: 'email', label: 'Email Analyzer', icon: <Mail size={18} />,   desc: 'Analyze email content' },
];

const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<Tab>('url');
  const [isMobileMenuOpen, setMobileMenu] = useState(false);

  const handleNav = (tab: Tab) => {
    setActiveTab(tab);
    setMobileMenu(false);
  };

  return (
    <div className="min-h-screen flex flex-col cyber-grid">
      <header className="glass sticky top-0 z-50 px-5 md:px-8 py-4 flex items-center justify-between border-b border-white/10">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/20 rounded-xl border border-primary/20">
            <Shield className="w-7 h-7 text-primary" />
          </div>
          <div>
            <h1 className="text-lg font-extrabold gradient-text leading-none tracking-tight">PhishDetect</h1>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest font-medium">Security Analysis Tool</p>
          </div>
        </div>

        <nav className="hidden md:flex items-center gap-1">
          {NAV_ITEMS.map(item => (
            <button
              key={item.id}
              onClick={() => handleNav(item.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-medium transition-all duration-200 ${
                activeTab === item.id
                  ? 'bg-primary/20 text-primary border border-primary/30'
                  : 'text-muted-foreground hover:bg-white/5 hover:text-foreground'
              }`}
            >
              {item.icon}{item.label}
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-3">
          <a href="https://github.com/matilda2a/PhishDetect" target="_blank" rel="noreferrer"
            className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 text-xs text-muted-foreground hover:text-white transition-all">
            <Code2 size={14} /> GitHub
          </a>
          <button className="md:hidden p-2 text-muted-foreground hover:text-white" onClick={() => setMobileMenu(o => !o)}>
            {isMobileMenuOpen ? <X size={22} /> : <Menu size={22} />}
          </button>
        </div>
      </header>

      {isMobileMenuOpen && (
        <div className="md:hidden glass fixed inset-0 z-40 pt-24 px-6 flex flex-col gap-3">
          {NAV_ITEMS.map(item => (
            <button
              key={item.id}
              onClick={() => handleNav(item.id)}
              className={`flex items-center gap-4 p-5 rounded-2xl text-left transition-all ${
                activeTab === item.id ? 'bg-primary/20 border border-primary/30 text-primary' : 'bg-white/5 border border-white/5'
              }`}
            >
              <div className={`p-2 rounded-lg ${activeTab === item.id ? 'bg-primary/20' : 'bg-white/10'}`}>{item.icon}</div>
              <div>
                <p className="font-bold">{item.label}</p>
                <p className="text-xs text-muted-foreground">{item.desc}</p>
              </div>
            </button>
          ))}
        </div>
      )}

      <main className="flex-1 container mx-auto px-4 py-8 md:px-6 lg:py-12 max-w-6xl">
        <div key={activeTab}>
          {activeTab === 'url'   && <URLScanner />}
          {activeTab === 'email' && <EmailAnalyzer />}
        </div>
      </main>

      <footer className="py-8 px-6 border-t border-white/5 text-center text-muted-foreground text-sm space-y-1">
        <p className="font-semibold">© 2026 PhishDetect — CSE Lab6</p>
      </footer>
    </div>
  );
};

export default App;

