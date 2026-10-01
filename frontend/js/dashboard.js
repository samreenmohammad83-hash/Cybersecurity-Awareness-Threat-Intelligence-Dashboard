async function getJSON(url){return await (await fetch(url)).json()}
async function load(){const s=await getJSON("/api/dashboard/stats");document.querySelector("#cards").innerHTML=Object.entries(s).map(([k,v])=>`<div class="card"><span>${label(k)}</span><b>${v}</b></div>`).join("");
const cats=await getJSON("/api/dashboard/groups/category");const sel=document.querySelector("#categoryFilter");cats.forEach(x=>sel.innerHTML+=`<option>${esc(x.label)}</option>`);
for(const f of ["severity","category","indicator_type","status"]){const data=await getJSON("/api/dashboard/groups/"+f);renderBars(f+"Chart",data)}
loadThreats()}
async function loadThreats(){const sev=document.querySelector("#severityFilter").value,cat=document.querySelector("#categoryFilter").value;let url="/api/threats?limit=80";if(sev)url+="&severity="+encodeURIComponent(sev);if(cat)url+="&category="+encodeURIComponent(cat);const d=await getJSON(url);document.querySelector("#threatRows").innerHTML=d.map(r=>`<tr><td><a class="link" href="/threat/${encodeURIComponent(r.threat_id)}">${esc(r.threat_id)}</a></td><td>${esc(r.threat_name)}</td><td>${esc(r.category)}</td><td>${esc(r.indicator_value)}</td><td>${esc(r.severity)}</td><td>${r.risk_score}</td><td>${r.confidence_score}</td><td>${esc(r.status)}</td></tr>`).join("")}
async function searchIOC(){const q=document.querySelector("#ioc").value;const d=await getJSON("/api/indicators/search?q="+encodeURIComponent(q));document.querySelector("#iocResult").textContent=JSON.stringify(d,null,2)}
async function generateAlerts(){const d=await (await fetch("/api/alerts/generate",{method:"POST"})).json();alert(`Created/refreshed ${d.created_or_refreshed} local alerts.`)}
function renderBars(id,data){const max=Math.max(...data.map(x=>x.count),1);document.querySelector("#"+id).innerHTML=data.slice(0,12).map(x=>`<div class="bar"><div class="barlabel"><span>${esc(x.label)}</span><b>${x.count}</b></div><div class="track"><div class="fill" style="width:${x.count/max*100}%"></div></div></div>`).join("")}
function label(x){return x.replaceAll("_"," ").replace(/\b\w/g,c=>c.toUpperCase())}
function esc(x){return String(x??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#039;"}[c]));}
load();
