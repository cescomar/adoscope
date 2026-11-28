function ConvertTo-AdoScopeHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][pscustomobject]$Report)

    $encode = { param($Value) [System.Net.WebUtility]::HtmlEncode([string]$Value) }
    $order = $script:Severities[($script:Severities.Count - 1)..0]   # Critical first
    $rank = @{ Expression = { [array]::IndexOf($script:Severities, $_.Severity) }; Descending = $true }
    $standards = @{}
    foreach ($rule in $Report.Rules) { $standards[$rule.Id] = (@($rule.Standards) | Where-Object { $_ }) -join ', ' }
    $findings = @($Report.Findings | Sort-Object $rank, CheckId, Project, Resource | ForEach-Object { ConvertTo-AdoScopeHtmlFinding -Finding $_ -Encode $encode -Standard $standards[$_.CheckId] }) -join [Environment]::NewLine
    $categories = @($Report.Rules.Category | Sort-Object -Unique | ForEach-Object { "<option value='$(& $encode $_)'>$(& $encode $_)</option>" }) -join ''
    $severity = @($order | ForEach-Object { "<option value='$(& $encode $_)'>$(& $encode $_)</option>" }) -join ''
    $counts = @(foreach ($sev in $order) {
            "<span class='badge sev-$(& $encode $sev)'>$(& $encode $sev): $(@($Report.Findings | Where-Object { $_.Severity -eq $sev -and -not $_.Suppressed }).Count)</span>"
        }) -join ' '
    $none = '<li>None.</li>'
    $gaps = @($Report.Checks | Where-Object Status -notin 'Evaluated', 'Disabled' | ForEach-Object { "<li><b>$(& $encode $_.CheckId)</b> ($(& $encode $_.Status)): $(& $encode $_.Message)</li>" }) -join ''
    if (-not $gaps) { $gaps = $none }
    $suppressions = @($Report.Suppressions | Where-Object Status -ne 'Active' | ForEach-Object { "<li><b>$(& $encode $_.Check)</b> ($(& $encode $_.Status)): $(& $encode $_.Target)</li>" }) -join ''
    if (-not $suppressions) { $suppressions = $none }
    $collections = @($Report.Collections | ForEach-Object { "<tr><td>$(& $encode $_.Name)</td><td>$(& $encode $_.Status)</td><td>$(& $encode $_.Count)</td><td>$(& $encode $_.Error)</td></tr>" }) -join ''
    @"
<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><meta http-equiv='Content-Security-Policy' content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'"><title>adoscope report</title><style>body{font:14px system-ui,sans-serif;margin:2rem;color:#1f2937}header{border-bottom:2px solid #2563eb;margin-bottom:1rem}h1{margin-bottom:.2rem}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{border:1px solid #d1d5db;padding:.45rem;text-align:left;vertical-align:top}th{background:#eff6ff}tr.suppressed{display:none;opacity:.6}.filters{display:flex;gap:1rem;align-items:center;flex-wrap:wrap}.severity{font-weight:700}@media print{.filters{display:none}body{margin:0}}</style></head><body>
<style>.badge{display:inline-block;padding:.15rem .55rem;border-radius:.8rem;font-weight:700;font-size:.85em;color:#fff;background:#6b7280}.sev-Critical{background:#7e22ce}.sev-High{background:#dc2626}.sev-Medium{background:#d97706}.sev-Low{background:#2563eb}.sev-Info{background:#6b7280}</style>
<header><h1>adoscope report</h1><p>Organization: <b>$(& $encode $Report.Organization)</b><br>Data collected: <b>$(& $encode $Report.Scope.CollectedAt)</b> ($(& $encode $Report.Scope.Mode))<br>Projects: $(& $encode (@($Report.Scope.Projects) -join ', '))<br>Generated: $(& $encode $Report.GeneratedAt)<br>Version: $(& $encode $Report.Version)</p></header>
<section><h2>Severity summary</h2><p>$counts</p><p>Unsuppressed findings. Checks fully evaluated: $(@($Report.Checks | Where-Object Status -eq 'Evaluated').Count) of $(@($Report.Checks | Where-Object Status -ne 'Disabled').Count).$(if ($Report.Baseline) { " Compared with baseline: <b>$(& $encode $Report.Baseline.New) new</b>, $(& $encode $Report.Baseline.Existing) already known, $(& $encode $Report.Baseline.Resolved) resolved, $(& $encode $Report.Baseline.Unverified) gone but not verifiable (data incomplete, scope or parameters changed)." })</p></section><section class='filters'><label>Category <select id='category'><option value=''>All</option>$categories</select></label><label>Severity <select id='severity'><option value=''>All</option>$severity</select></label><label><input id='suppressed' type='checkbox'> Show suppressed findings</label></section>
<section><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Check</th><th>Title</th><th>Project</th><th>Resource</th><th>Detail</th><th>Remediation</th></tr></thead><tbody id='findings'>$findings</tbody></table></section>
<section><h2>Coverage gaps</h2><ul>$gaps</ul></section><section><h2>Suppressions requiring attention</h2><ul>$suppressions</ul></section><section><h2>Collections</h2><table><thead><tr><th>Name</th><th>Status</th><th>Count</th><th>Error</th></tr></thead><tbody>$collections</tbody></table></section>
<script>const c=document.getElementById('category'),s=document.getElementById('severity'),x=document.getElementById('suppressed');function f(){document.querySelectorAll('#findings tr').forEach(r=>r.style.display=(!x.checked&&r.dataset.suppressed==='true')||(c.value&&r.dataset.category!==c.value)||(s.value&&r.dataset.severity!==s.value)?'none':'table-row')}[c,s,x].forEach(e=>e.addEventListener('change',f));f();</script></body></html>
"@
}

function ConvertTo-AdoScopeHtmlFinding {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][pscustomobject]$Finding, [Parameter(Mandatory)][scriptblock]$Encode, [string]$Standard)

    $value = { param($Name) & $Encode $Finding.$Name }
    $standardNote = if ($Standard) { "<br><small>$(& $Encode $Standard)</small>" } else { '' }
    "<tr class='$(& $Encode $(if ($Finding.Suppressed) { 'suppressed' } else { '' }))' data-category='$(& $value 'Category')' data-severity='$(& $value 'Severity')' data-suppressed='$($Finding.Suppressed.ToString().ToLowerInvariant())'><td class='severity'><span class='badge sev-$(& $value 'Severity')'>$(& $value 'Severity')</span></td><td>$(& $value 'CheckId')$standardNote</td><td>$(& $value 'Title')</td><td>$(& $value 'Project')</td><td>$(& $value 'Resource')</td><td>$(& $value 'Detail')</td><td>$(& $value 'Remediation')</td></tr>"
}
