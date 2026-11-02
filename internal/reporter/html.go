package reporter

import (
	"html/template"
	"io"
	"time"

	"redirx/internal/models"
	"redirx/pkg/version"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedirX Security Audit Report</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --border: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --accent: #38bdf8;
            --danger: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.15);
            --warning: #f59e0b;
            --warning-bg: rgba(245, 158, 11, 0.15);
            --success: #10b981;
            --success-bg: rgba(16, 185, 129, 0.15);
            --info: #64748b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; }
        body { background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; }
        header { border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; }
        .logo-area h1 { font-size: 1.75rem; color: var(--text); font-weight: 700; }
        .logo-area p { color: var(--text-muted); font-size: 0.9rem; }
        .meta-area { text-align: right; color: var(--text-muted); font-size: 0.85rem; }
        
        .grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; }
        .card .title { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.5rem; }
        .card .value { font-size: 1.75rem; font-weight: 700; color: var(--text); }
        .card.confirmed .value { color: var(--danger); }
        .card.potential .value { color: var(--warning); }
        .card.fp .value { color: var(--info); }
        
        .controls { display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
        .search-box { flex: 1; min-width: 250px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 0.6rem 1rem; color: var(--text); outline: none; }
        .search-box:focus { border-color: var(--accent); }
        
        .finding-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }
        .finding-header { padding: 1rem 1.25rem; background: rgba(255,255,255,0.02); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; cursor: pointer; flex-wrap: wrap; gap: 0.75rem; }
        .finding-header:hover { background: var(--surface-hover); }
        .badge { padding: 0.25rem 0.6rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; }
        .badge.confirmed { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); }
        .badge.potential { background: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning); }
        .badge.false-positive { background: rgba(148, 163, 184, 0.15); color: var(--text-muted); border: 1px solid var(--info); }
        
        .finding-body { padding: 1.25rem; display: block; }
        .detail-row { margin-bottom: 0.75rem; display: flex; flex-wrap: wrap; gap: 0.5rem; }
        .detail-label { font-weight: 600; color: var(--text-muted); min-width: 140px; font-size: 0.9rem; }
        .detail-value { font-family: monospace; font-size: 0.9rem; word-break: break-all; color: var(--text); }
        
        .chain-box { margin-top: 1rem; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; }
        .chain-title { font-size: 0.85rem; font-weight: 600; color: var(--accent); margin-bottom: 0.5rem; }
        .hop-item { font-family: monospace; font-size: 0.85rem; padding: 0.35rem 0; border-bottom: 1px dashed var(--border); }
        .hop-item:last-child { border-bottom: none; }
        .hop-status { font-weight: 700; color: var(--warning); }
        
        .notes-box { margin-top: 1rem; background: rgba(56, 189, 248, 0.05); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 6px; padding: 0.75rem 1rem; font-size: 0.85rem; color: #bae6fd; }
        .notes-box ul { margin-left: 1.25rem; }
        
        footer { margin-top: 3rem; text-align: center; color: var(--text-muted); font-size: 0.85rem; border-top: 1px solid var(--border); padding-top: 1.5rem; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-area">
                <h1>RedirX Security Audit</h1>
                <p>Advanced Open Redirect Vulnerability Analysis Report</p>
            </div>
            <div class="meta-area">
                <div>Engine: RedirX v{{.EngineVersion}}</div>
                <div>Developer: {{.Author}}</div>
                <div>Generated: {{.GeneratedAt}}</div>
            </div>
        </header>

        <section class="grid-stats">
            <div class="card">
                <div class="title">Total Targets</div>
                <div class="value">{{.Summary.TotalTargets}}</div>
            </div>
            <div class="card confirmed">
                <div class="title">Confirmed Vulns</div>
                <div class="value">{{.Summary.ConfirmedCount}}</div>
            </div>
            <div class="card potential">
                <div class="title">Potential Findings</div>
                <div class="value">{{.Summary.PotentialCount}}</div>
            </div>
            <div class="card fp">
                <div class="title">False Positives</div>
                <div class="value">{{.Summary.FalsePositiveCount}}</div>
            </div>
            <div class="card">
                <div class="title">Total Requests</div>
                <div class="value">{{.Summary.TotalRequests}}</div>
            </div>
            <div class="card">
                <div class="title">Duration</div>
                <div class="value">{{.DurationFormatted}}</div>
            </div>
        </section>

        <div class="controls">
            <input type="text" id="searchInput" class="search-box" placeholder="Filter findings by URL, parameter, payload..." onkeyup="filterFindings()">
        </div>

        <section id="findingsList">
            {{range .Findings}}
            <div class="finding-card item-card" data-search="{{.OriginalURL}} {{.VulnerableURL}} {{.Parameter}} {{.Payload}} {{.Classification}}">
                <div class="finding-header">
                    <div>
                        <span class="badge {{if eq .Classification "CONFIRMED"}}confirmed{{else if eq .Classification "POTENTIAL"}}potential{{else}}false-positive{{end}}">{{.Classification}}</span>
                        <strong style="margin-left: 0.5rem;">{{.VulnerabilityType}}</strong>
                        <span style="color: var(--text-muted); margin-left: 0.5rem; font-size: 0.85rem;">(Confidence: {{.Confidence}})</span>
                    </div>
                    <div style="font-family: monospace; font-size: 0.85rem; color: var(--accent);">Param: {{.Parameter}}</div>
                </div>
                <div class="finding-body">
                    <div class="detail-row">
                        <div class="detail-label">Original URL:</div>
                        <div class="detail-value">{{.OriginalURL}}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Tested URL:</div>
                        <div class="detail-value">{{.VulnerableURL}}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Payload:</div>
                        <div class="detail-value">{{.Payload}}</div>
                    </div>
                    <div class="detail-row">
                        <div class="detail-label">Final Destination:</div>
                        <div class="detail-value" style="color: var(--danger);">{{.FinalDestination}}</div>
                    </div>

                    {{if .RedirectChain}}
                    <div class="chain-box">
                        <div class="chain-title">Observed Redirect Chain ({{len .RedirectChain}} hops)</div>
                        {{range .RedirectChain}}
                        <div class="hop-item">
                            <span class="hop-status">[{{.StatusCode}}]</span> {{.URL}}
                            {{if .LocationHeader}}<br>&nbsp;&nbsp;&rarr; Location: <span style="color: var(--danger);">{{.LocationHeader}}</span>{{end}}
                            {{if .DestinationURL}}<br>&nbsp;&nbsp;&rarr; Resolved: {{.DestinationURL}}{{end}}
                            {{if .Error}}<br>&nbsp;&nbsp;&rarr; <span style="color: var(--danger);">Error: {{.Error}}</span>{{end}}
                        </div>
                        {{end}}
                    </div>
                    {{end}}

                    {{if .ValidationNotes}}
                    <div class="notes-box">
                        <strong>Validation & Analysis Notes:</strong>
                        <ul>
                            {{range .ValidationNotes}}
                            <li>{{.}}</li>
                            {{end}}
                        </ul>
                    </div>
                    {{end}}
                </div>
            </div>
            {{else}}
            <div class="card" style="text-align: center; color: var(--text-muted); padding: 3rem;">
                No findings to display.
            </div>
            {{end}}
        </section>

        <footer>
            Generated by RedirX v{{.EngineVersion}} by {{.Author}} &bull; Open Redirect Detection & Analysis Engine
        </footer>
    </div>

    <script>
        function filterFindings() {
            var q = document.getElementById('searchInput').value.toLowerCase();
            var cards = document.getElementsByClassName('item-card');
            for (var i = 0; i < cards.length; i++) {
                var searchData = cards[i].getAttribute('data-search').toLowerCase();
                if (searchData.indexOf(q) > -1) {
                    cards[i].style.display = 'block';
                } else {
                    cards[i].style.display = 'none';
                }
            }
        }
    </script>
</body>
</html>`

type htmlData struct {
	EngineVersion     string
	Author            string
	GeneratedAt       string
	DurationFormatted string
	Summary           models.ScanSummary
	Findings          []models.Finding
}

// WriteHTMLReport generates a responsive, standalone HTML report document.
func WriteHTMLReport(w io.Writer, summary models.ScanSummary, findings []models.Finding) error {
	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	data := htmlData{
		EngineVersion:     version.Version,
		Author:            version.Author,
		GeneratedAt:       time.Now().Format("2006-01-02 15:04:05 MST"),
		DurationFormatted: summary.Duration.Round(time.Millisecond).String(),
		Summary:           summary,
		Findings:          findings,
	}

	return tmpl.Execute(w, data)
}

