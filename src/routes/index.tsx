import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { 
  ShieldCheck, Camera, Search, Loader2, AlertTriangle, ExternalLink, 
  Globe, Tag, User, Clock, ShieldAlert, Calendar, ChevronLeft, ChevronRight
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { QrScanner } from "@/components/qr-scanner";
import { SafetyReportView } from "@/components/safety-report";
import { analyzeUrlAsync, type SafetyReport } from "@/lib/url-safety";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "QR Safety Checker — Live TweetFeed Security & Historical Archive" },
      { name: "description", content: "Scan QR codes and verify links against live and historical Twitter/X threat intelligence feeds." },
    ],
  }),
  component: Index,
});

interface FeedItem {
  domain: string;
  tags: string[];
  source: string;
  date: string;
  tweet?: string;
}

const API_BASE_URL = typeof window !== "undefined" && (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1")
  ? "http://localhost:8000"
  : (import.meta.env.VITE_API_URL || "https://api.tweetfeed.live");

function Index() {
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [manualInput, setManualInput] = useState("");
  const [report, setReport] = useState<SafetyReport | null>(null);

  // Pagination & Filter States
  const [feedItems, setFeedItems] = useState<FeedItem[]>([]);
  const [page, setPage] = useState<number>(1);
  const [limit, setLimit] = useState<number>(5);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [totalRecords, setTotalRecords] = useState<number>(0);
  const [selectedTag, setSelectedTag] = useState<string>("all");
  const [feedSearch, setFeedSearch] = useState<string>("");
  const [dateFilter, setDateFilter] = useState<string>("");
  const [showFullFeed, setShowFullFeed] = useState<boolean>(false);

  // Fetch paginated and filtered historical feed from API
  const fetchFeedData = () => {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
      tag: selectedTag,
      search: feedSearch,
      date: dateFilter
    });

    fetch(`${API_BASE_URL}/api/feed?${params.toString()}`)
      .then((res) => res.json())
      .then((data) => {
        if (data.items) {
          setFeedItems(data.items);
          setTotalPages(data.total_pages || 1);
          setTotalRecords(data.total || data.items.length);
        }
      })
      .catch(() => {
        // Local Fallback
        setFeedItems([
          { domain: "resona-bank.aochz.com", tags: ["#phishing", "#bank-scam"], source: "@skocherhan", date: "2026-07-30 01:15", tweet: "https://x.com" },
          { domain: "pdf.adodefile.cam", tags: ["#phishing"], source: "@PhishStats", date: "2026-07-30 00:10", tweet: "https://x.com" },
          { domain: "vipking.top", tags: ["#phishing", "#malware"], source: "@skocherhan", date: "2026-07-30 01:15", tweet: "https://x.com" },
          { domain: "elettronicaessenziale.com", tags: ["#phishing"], source: "@skocherhan", date: "2026-07-30 01:15", tweet: "https://x.com" },
          { domain: "catoynan.top", tags: ["#phishing"], source: "@skocherhan", date: "2026-07-30 01:15", tweet: "https://x.com" },
        ]);
        setTotalPages(1);
        setTotalRecords(5);
      });
  };

  useEffect(() => {
    fetchFeedData();
  }, [page, limit, selectedTag, feedSearch, dateFilter]);

  const handleProcessUrl = async (value: string) => {
    setLoading(true);
    setScanning(false);
    try {
      const res = await analyzeUrlAsync(value);
      setReport(res);
    } finally {
      setLoading(false);
    }
  };

  const reset = () => {
    setReport(null);
    setScanning(true);
  };

  const getTagBadgeClass = (tag: string) => {
    const t = tag.toLowerCase();
    if (t.includes("phish")) return "bg-red-500/10 text-red-500 border-red-500/20";
    if (t.includes("malware") || t.includes("c2")) return "bg-purple-500/10 text-purple-400 border-purple-500/20";
    if (t.includes("scam")) return "bg-amber-500/10 text-amber-500 border-amber-500/20";
    return "bg-blue-500/10 text-blue-400 border-blue-500/20";
  };

  return (
    <main className="min-h-screen bg-background">
      <div className="mx-auto max-w-md px-4 py-6 sm:py-10">
        <header className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-bold leading-tight text-foreground">QR Safety Checker</h1>
              <p className="text-xs text-muted-foreground">Powered by TweetFeed OSINT API</p>
            </div>
          </div>
          <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/10 px-2.5 py-1 text-xs font-semibold text-emerald-500 border border-emerald-500/20">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" /> Live API
          </span>
        </header>

        {loading && (
          <div className="rounded-2xl border bg-card p-8 text-center space-y-3 shadow-sm">
            <Loader2 className="h-8 w-8 animate-spin mx-auto text-primary" />
            <h3 className="font-semibold text-foreground">Checking TweetFeed Intelligence...</h3>
            <p className="text-xs text-muted-foreground">Cross-referencing scanned link against Twitter/X security researcher feeds.</p>
          </div>
        )}

        {!report && !scanning && !loading && (
          <div className="space-y-6">
            <div className="rounded-2xl border bg-card p-6 text-center shadow-sm">
              <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
                <Camera className="h-8 w-8 text-primary" />
              </div>
              <h2 className="text-base font-semibold text-foreground">Check a QR code or Link</h2>
              <p className="mt-1 text-sm text-muted-foreground">
                We'll decode it and check TweetFeed threat intelligence for phishing or malware warnings.
              </p>
              
              <Button size="lg" className="mt-5 w-full font-semibold" onClick={() => setScanning(true)}>
                <Camera className="mr-2 h-5 w-5" /> Scan QR with Camera
              </Button>

              <div className="mt-4 pt-4 border-t flex gap-2">
                <input
                  type="text"
                  placeholder="Paste URL or domain (e.g. resona-bank.aochz.com)..."
                  value={manualInput}
                  onChange={(e) => setManualInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && manualInput.trim() && handleProcessUrl(manualInput.trim())}
                  className="flex-1 rounded-lg border bg-background px-3 py-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-primary"
                />
                <Button size="sm" onClick={() => manualInput.trim() && handleProcessUrl(manualInput.trim())}>
                  <Search className="h-4 w-4" />
                </Button>
              </div>
            </div>

            {/* Organized Live Threat Feed & Historical Archive Section */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <ShieldAlert className="h-4 w-4 text-destructive" />
                  Historical Bad Domains ({totalRecords})
                </h3>
                <Button 
                  variant="ghost" 
                  size="sm" 
                  className="h-7 text-xs text-primary hover:text-primary/80"
                  onClick={() => {
                    const newShow = !showFullFeed;
                    setShowFullFeed(newShow);
                    setLimit(newShow ? 10 : 5);
                    setPage(1);
                  }}
                >
                  {showFullFeed ? "Compact View" : "Full Archive View"}
                </Button>
              </div>

              {/* Tag Filter Bar */}
              <div className="flex gap-1.5 overflow-x-auto pb-1 text-xs">
                {["all", "phishing", "malware", "scam", "c2"].map((tag) => (
                  <button
                    key={tag}
                    onClick={() => { setSelectedTag(tag); setPage(1); }}
                    className={`px-2.5 py-1 rounded-full font-medium transition-all ${
                      selectedTag === tag
                        ? "bg-primary text-primary-foreground shadow-sm"
                        : "bg-muted/60 text-muted-foreground hover:bg-muted"
                    }`}
                  >
                    {tag === "all" ? "All" : `#${tag}`}
                  </button>
                ))}
              </div>

              {/* Date Filter & Search Bar */}
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="relative">
                  <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                  <input
                    type="text"
                    placeholder="Search domain..."
                    value={feedSearch}
                    onChange={(e) => { setFeedSearch(e.target.value); setPage(1); }}
                    className="w-full rounded-lg border bg-background pl-8 pr-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
                <div className="relative">
                  <Calendar className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
                  <input
                    type="text"
                    placeholder="Filter date (YYYY-MM-DD)..."
                    value={dateFilter}
                    onChange={(e) => { setDateFilter(e.target.value); setPage(1); }}
                    className="w-full rounded-lg border bg-background pl-8 pr-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>
              </div>

              {/* Feed List Cards */}
              <div className="space-y-2.5">
                {feedItems.length === 0 ? (
                  <div className="rounded-xl border bg-card/40 p-4 text-center text-xs text-muted-foreground">
                    No bad domains found for selected filters.
                  </div>
                ) : (
                  feedItems.map((item, idx) => (
                    <div key={idx} className="rounded-xl border bg-card/70 p-3.5 text-xs shadow-xs space-y-2 hover:border-primary/40 transition-colors">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 min-w-0">
                          <Globe className="h-3.5 w-3.5 text-destructive shrink-0" />
                          <span className="font-mono font-bold text-destructive truncate">{item.domain}</span>
                        </div>
                        <Button 
                          size="sm" 
                          variant="secondary" 
                          className="h-7 px-2.5 text-[11px] font-semibold shrink-0"
                          onClick={() => handleProcessUrl(item.domain)}
                        >
                          Check Link
                        </Button>
                      </div>

                      <div className="flex items-center justify-between text-[11px] text-muted-foreground border-t border-border/40 pt-2 flex-wrap gap-1">
                        <div className="flex items-center gap-1.5">
                          <User className="h-3 w-3 text-primary" />
                          <span className="font-medium text-foreground">{item.source}</span>
                          <span className="text-muted-foreground">•</span>
                          <Clock className="h-3 w-3" />
                          <span>{item.date || "Recent"}</span>
                        </div>

                        <div className="flex items-center gap-1 flex-wrap">
                          {(item.tags || []).map((t, tidx) => (
                            <span key={tidx} className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded border text-[10px] font-mono ${getTagBadgeClass(t)}`}>
                              <Tag className="h-2.5 w-2.5" />
                              {t}
                            </span>
                          ))}
                          {item.tweet && (
                            <a href={item.tweet} target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-primary ml-1" title="Source Tweet">
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          )}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Pagination Controls */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between border-t pt-3 text-xs text-muted-foreground">
                  <span>Page <strong>{page}</strong> of <strong>{totalPages}</strong></span>
                  <div className="flex gap-2">
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="h-7 px-2.5 text-xs" 
                      disabled={page <= 1}
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                    >
                      <ChevronLeft className="h-3.5 w-3.5 mr-1" /> Prev
                    </Button>
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="h-7 px-2.5 text-xs" 
                      disabled={page >= totalPages}
                      onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    >
                      Next <ChevronRight className="h-3.5 w-3.5 ml-1" />
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {scanning && !loading && (
          <div className="space-y-4">
            <QrScanner active={scanning} onDecoded={handleProcessUrl} />
            <p className="text-center text-sm text-muted-foreground">
              Point your camera at a QR code.
            </p>
            <Button variant="outline" className="w-full" onClick={() => setScanning(false)}>
              Cancel
            </Button>
          </div>
        )}

        {report && !loading && <SafetyReportView report={report} onReset={reset} />}
      </div>
    </main>
  );
}
