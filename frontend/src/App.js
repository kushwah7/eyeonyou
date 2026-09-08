import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import './App.css';

const API = 'http://localhost:8000';

const TABS = [
  { id:'email',    icon:'📧', label:'EMAIL',     type:'text', placeholder:'Enter email address (ex: user@gmail.com)' },
  { id:'ip',       icon:'🌐', label:'IP LOOKUP', type:'text', placeholder:'Enter IP address (ex: 8.8.8.8)' },
  { id:'website',  icon:'🔗', label:'WEBSITE',   type:'text', placeholder:'Enter website URL (ex: google.com)' },
  { id:'image',    icon:'🖼', label:'IMAGE',     type:'file', placeholder:'Upload image file' },
  { id:'hash',     icon:'🔐', label:'HASH',      type:'text', placeholder:'Enter hash string to analyze...' },
  { id:'log',      icon:'📋', label:'LOG FILE',  type:'file', placeholder:'Upload log file' },
];

const SCAN_TEXTS = ['PLEASE WAIT...'];

function getSeverityColor(s){
  if(s==='CRITICAL') return '#ff003c';
  if(s==='HIGH')     return '#ff6600';
  if(s==='MEDIUM')   return '#ffaa00';
  if(s==='LOW')      return '#00ff88';
  return '#00ccff';
}

function InfoGrid({data}){
  if(!data) return null;
  return(
    <div className="info-grid">
      {Object.entries(data).map(([k,v],i)=>(
        v && typeof v!=='object' && (
          <div key={i} className="info-item">
            <div className="info-label">{k.replace(/_/g,' ').toUpperCase()}</div>
            <div className="info-value">{String(v)}</div>
          </div>
        )
      ))}
    </div>
  );
}

function EyeLogo(){
  const eyeRef   = useRef(null);
  const pupilRef = useRef(null);
  const [blink, setBlink] = useState(false);

  useEffect(()=>{
    const handleMouseMove = (e)=>{
      if(!eyeRef.current || !pupilRef.current) return;
      const eye = eyeRef.current.getBoundingClientRect();
      const cx  = eye.left + eye.width/2;
      const cy  = eye.top  + eye.height/2;
      const dx  = e.clientX - cx;
      const dy  = e.clientY - cy;
      const angle = Math.atan2(dy, dx);
      const dist  = Math.min(Math.sqrt(dx*dx+dy*dy), 28);
      const x = Math.cos(angle)*dist;
      const y = Math.sin(angle)*dist;
      pupilRef.current.style.transform = `translate(calc(-50% + ${x}px), calc(-50% + ${y}px))`;
    };
    window.addEventListener('mousemove', handleMouseMove);
    return ()=>window.removeEventListener('mousemove', handleMouseMove);
  },[]);

  useEffect(()=>{
    const iv = setInterval(()=>{
      setBlink(true);
      setTimeout(()=>setBlink(false), 160);
    }, 3800);
    return ()=>clearInterval(iv);
  },[]);

  return(
    <div className="eye-logo-wrapper">
      <div className="eye-orbit eye-orbit1" style={{display:'none'}}></div>
      <div className="eye-orbit eye-orbit2" style={{display:'none'}}></div>
      <div className="eye-orbit eye-orbit3" style={{display:'none'}}></div>
      <div className="eye-hex-ring" style={{display:'none'}}></div>
      <div className={`eye-socket ${blink?'blink':''}`} ref={eyeRef}>
        <div className="eye-white">
          <div className="eye-iris">
            <div className="eye-iris-ring1"></div>
            <div className="eye-iris-ring2"></div>
            <div className="eye-pupil" ref={pupilRef}>
              <div className="eye-pupil-core"></div>
              <div className="eye-reflection"></div>
            </div>
          </div>
        </div>
        <div className={`eye-lid eye-lid-top ${blink?'blink':''}`}></div>
        <div className={`eye-lid eye-lid-bot ${blink?'blink':''}`}></div>
      </div>
      <div className="eye-scan-line"></div>
    </div>
  );
}

export default function App(){
  const [tab,setTab]           = useState('email');
  const [query,setQuery]       = useState('');
  const [file,setFile]         = useState(null);
  const [result,setResult]     = useState(null);
  const [loading,setLoading]   = useState(false);
  const [error,setError]       = useState('');
  const [validErr,setValidErr] = useState('');
  const [scanText,setScanText] = useState('');
  const [totalScans,setTotalScans] = useState(Math.floor(Math.random()*9000)+1000);
  const [vulnConfirmed,setVulnConfirmed] = useState(false);
  const inputRef  = useRef(null);
  const matrixRef = useRef(null);
  const currentTab = TABS.find(t=>t.id===tab);
  const isFileTab  = currentTab?.type==='file';

  useEffect(()=>{
    const canvas = matrixRef.current;
    if(!canvas) return;
    const ctx = canvas.getContext('2d');
    const resize = ()=>{ canvas.width=window.innerWidth; canvas.height=window.innerHeight; };
    resize();
    const chars = '01アイウエオカキクケコサシスセソ⊕⊗⊙◉◈◎⊛⊜⊝⊞';
    const fs = 13;
    const cols = Math.floor(canvas.width/fs);
    const drops = Array(cols).fill(1);
    const draw = ()=>{
      ctx.fillStyle='rgba(2,12,18,0.06)';
      ctx.fillRect(0,0,canvas.width,canvas.height);
      drops.forEach((y,i)=>{
        const alpha = Math.random()*0.55+0.1;
        const g = Math.floor(Math.random()*180+60);
        const b = Math.min(g+80,255);
        ctx.fillStyle=`rgba(0,${g},${b},${alpha})`;
        ctx.font=`${fs}px monospace`;
        ctx.fillText(chars[Math.floor(Math.random()*chars.length)], i*fs, y*fs);
        if(y*fs>canvas.height && Math.random()>0.975) drops[i]=0;
        drops[i]++;
      });
    };
    const iv=setInterval(draw,55);
    window.addEventListener('resize',resize);
    return()=>{ clearInterval(iv); window.removeEventListener('resize',resize); };
  },[]);

  useEffect(()=>{
    setQuery('');setFile(null);setResult(null);setError('');setValidErr('');setVulnConfirmed(false);
    setTimeout(()=>inputRef.current?.focus(),100);
  },[tab]);

  useEffect(()=>{
    if(!loading) return;
    let i=0;
    const iv=setInterval(()=>{ setScanText(SCAN_TEXTS[i++%SCAN_TEXTS.length]); },900);
    return()=>clearInterval(iv);
  },[loading]);

  function handleInput(e){
    setQuery(e.target.value);
    setValidErr('');
  }

  function validate(){
    if(!query && !isFileTab) return '⚠ INPUT CANNOT BE EMPTY';
    if(isFileTab){ if(!file) return '⚠ PLEASE SELECT A FILE'; return null; }
    if(tab==='email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(query))
      return '⚠ INVALID EMAIL — Must contain @ and domain';
    if(tab==='ip' && !/^\d+\.\d+\.\d+\.\d+$/.test(query))
      return '⚠ INVALID IP — Format: 192.168.1.1';
    if(tab==='hash' && query.length<8)
      return '⚠ HASH TOO SHORT — Min 8 characters';
    return null;
  }

  async function handleSearch(){
    const err=validate();
    if(err){ setValidErr(err); return; }
    setLoading(true); setError(''); setResult(null); setValidErr(''); setVulnConfirmed(false);
    try{
      let res;
      if(tab==='email'){
        const report = await axios.get(`${API}/check/email/${query}`);
        res = report;
      } else if(tab==='ip'){
        const ip = await axios.get(`${API}/lookup/ip/${query}`);
        res = ip;
      } else if(tab==='website'){
        const website = await axios.get(`${API}/lookup/website?url=${query}`);
        res = website;
      } else if(tab==='image'){
        const fd=new FormData(); fd.append('file',file);
        const fd2=new FormData(); fd2.append('file',file);
        const [basic, full] = await Promise.all([
          axios.post(`${API}/lookup/image`,fd),
          axios.post(`${API}/lookup/image/full`,fd2)
        ]);
        let faceData = null;
        try {
          const fd3=new FormData(); fd3.append('file',file);
          const faceRes = await axios.post(`${API}/lookup/face`,fd3, {timeout: 25000});
          faceData = faceRes.data;
        } catch(e) {
          faceData = {face_detected: false, deepfake_check: {verdict: "Timeout"}};
        }
        res = {data: {...basic.data, full: full.data, face: faceData}};
      } else if(tab==='hash'){
        const hash = await axios.get(`${API}/lookup/hash?hash_str=${query}`);
        res = hash;
      } else if(tab==='log'){
        const fd=new FormData(); fd.append('file',file);
        const log = await axios.post(`${API}/lookup/log`,fd);
        res = log;
      }
      setResult(res.data);
      setTotalScans(p=>p+1);
    } catch(e) {
      setError('CONNECTION FAILED. ENSURE BACKEND IS RUNNING ON PORT 8000');
    }
    setLoading(false);
  }

  function renderResult(){
    if(!result) return null;

    if(tab==='email'){
      const a=result.analysis||{};
      return(
        <>
        <div className="risk-card" style={{borderColor:getSeverityColor(a.severity)+'55'}}>
          <h2>◈ THREAT ASSESSMENT</h2>
          <div className="risk-score" style={{color:getSeverityColor(a.severity),textShadow:`0 0 60px ${getSeverityColor(a.severity)}`}}>
            {a.overall_risk}<span style={{fontSize:'0.22em',opacity:0.35}}>/100</span>
          </div>
          <div className="severity" style={{background:getSeverityColor(a.severity)+'16',border:`1px solid ${getSeverityColor(a.severity)}44`,color:getSeverityColor(a.severity)}}>
            {a.color} {a.severity}
          </div>
          <p className="risk-total">◉ BREACHES: <b style={{color:'#fff'}}>{a.total_breaches}</b></p>
        </div>
        {a.all_leaked_fields?.length>0 && (
          <div className="card"><h3>◈ LEAKED DATA TYPES</h3>
            <div className="tags">{a.all_leaked_fields.map((f,i)=><span key={i} className="tag">{f}</span>)}</div>
          </div>
        )}
        {a.analyzed_breaches?.length>0 && (
          <div className="card"><h3>◉ BREACH INTELLIGENCE</h3>
            {a.analyzed_breaches.map((b,i)=>(
              <div key={i} className="breach-item">
                <div className="breach-header">
                  <span className="breach-name">⬡ {b.name||'UNKNOWN'}</span>
                  <span className="badge" style={{background:getSeverityColor(b.severity)+'16',border:`1px solid ${getSeverityColor(b.severity)}44`,color:getSeverityColor(b.severity)}}>{b.severity}</span>
                </div>
                <div className="breach-meta">
                  <span>◎ {b.date||'UNKNOWN'}</span>
                  <span>⚠ RISK: {b.risk_score}/100</span>
                </div>
                <div className="tags" style={{marginTop:'8px'}}>
                  {(b.leaked_fields||[]).map((f,j)=><span key={j} className="tag danger-tag">{f}</span>)}
                </div>
                <div className="breach-note">⚠ Data circulating on dark web. Immediate action required!</div>
              </div>
            ))}
          </div>
        )}
        {result.ai_advice && (<div className="card ai-card"><h3>◈ AI SECURITY ADVICE</h3><p>{result.ai_advice}</p></div>)}
        {result.alert_sent?.sent && (<div className="card success-card"><h3>◉ ALERT SENT!</h3><p>Breach report sent to inbox automatically</p></div>)}
        {a.total_breaches===0 && (<div className="card safe-card"><h3>◈ TARGET SECURE ✅</h3><p>NO BREACHES FOUND FOR {query.toUpperCase()}</p></div>)}
        </>
      );
    }

    if(tab==='ip'){
      return(
        <>
        <div className="card"><h3>🌐 BASIC INFO</h3><InfoGrid data={result.basic}/></div>
        <div className="card"><h3>🔒 SECURITY FLAGS</h3>
          <div className="tags">{Object.entries(result.security||{}).map(([k,v],i)=>(
            typeof v==='boolean' && <span key={i} className={`tag ${v?'danger-tag':''}`}>{v?'⚠':'✓'} {k.replace(/_/g,' ').toUpperCase()}</span>
          ))}</div>
        </div>
        <div className="card"><h3>📡 NETWORK INFO</h3><InfoGrid data={result.network}/></div>
        </>
      );
    }

    if(tab==='website'){
      return(
        <>
        {/* SCAN INFO */}
        {result.scan_info && (
          <div className="card" style={{
            borderColor: result.scan_info.scanner_ip_hidden ? 'rgba(0,255,136,0.3)' : 'rgba(255,0,60,0.4)',
            background: result.scan_info.scanner_ip_hidden ? 'transparent' : 'rgba(255,0,60,0.05)'
          }}>
            <h3 style={{color: result.scan_info.scanner_ip_hidden ? '#00ff88' : '#ff003c'}}>
              {result.scan_info.scanner_ip_hidden ? '🛡 ANONYMOUS SCAN' : '⚠️ IP EXPOSED'}
            </h3>
            <div className="info-grid">
              <div className="info-item">
                <div className="info-label">IP HIDDEN</div>
                <div className="info-value" style={{color: result.scan_info.scanner_ip_hidden ? '#00ff88' : '#ff003c'}}>
                  {result.scan_info.scanner_ip_hidden ? '✅ YES' : '❌ NO'}
                </div>
              </div>
              <div className="info-item">
                <div className="info-label">VIA</div>
                <div className="info-value">{result.scan_info.via || 'Direct'}</div>
              </div>
              <div className="info-item">
                <div className="info-label">DETECTED IP</div>
                <div className="info-value" style={{fontFamily:'monospace'}}>{result.scan_info.detected_ip || 'Unknown'}</div>
              </div>
              <div className="info-item">
                <div className="info-label">LOCATION</div>
                <div className="info-value">{result.scan_info.detected_country || 'Unknown'}</div>
              </div>
            </div>
            <p style={{
              color: result.scan_info.scanner_ip_hidden ? 'rgba(0,255,136,0.6)' : '#ff6666',
              fontSize:'0.75em',
              marginTop:'8px',
              fontWeight: result.scan_info.scanner_ip_hidden ? 'normal' : 'bold'
            }}>
              ⚠ {result.scan_info.warning}
            </p>
          </div>
        )}

        <div className="card"><h3>🔗 BASIC INFO</h3><InfoGrid data={result.basic}/></div>
        
        <div className="card"><h3>🔒 SECURITY HEADERS</h3><InfoGrid data={result.security_headers}/></div>
        
        <div className="card"><h3>👤 WHOIS DATA</h3><InfoGrid data={result.whois}/></div>
        
        <div className="card"><h3>📡 DNS RECORDS</h3>
          {Object.entries(result.dns||{}).map(([type,records],i)=>(
            records && records.length>0 && <div key={i} style={{marginBottom:'12px'}}>
              <div className="info-label">{type} RECORDS</div>
              {records.map((r,j)=><div key={j} style={{fontSize:'0.75em',color:'rgba(0,220,200,0.38)',marginTop:'3px',fontFamily:'monospace'}}>{r}</div>)}
            </div>
          ))}
        </div>
        
        <div className="card"><h3>🔒 SSL CERTIFICATE</h3><InfoGrid data={result.ssl}/></div>
        
        {result.technology?.stack?.length>0 && (
          <div className="card"><h3>⚙ TECHNOLOGIES</h3>
            <div className="tags">{result.technology.stack.map((t,i)=><span key={i} className="tag">{t}</span>)}</div>
          </div>
        )}
        
        {result.pages?.admin_pages?.length>0 && (
          <div className="card"><h3>🚨 ADMIN PAGES FOUND</h3>
            {result.pages.admin_pages.map((p,i)=>(
              <div key={i} className="breach-item">
                <div className="breach-header">
                  <span className="breach-name">⬡ {p.path}</span>
                  <span className="badge" style={{
                    background: p.status===200 ? 'rgba(255,0,60,0.16)' : p.status===403 ? 'rgba(255,170,0,0.16)' : 'rgba(0,255,136,0.16)',
                    border: `1px solid ${p.status===200 ? '#ff003c' : p.status===403 ? '#ffaa00' : '#00ff88'}44`,
                    color: p.status===200 ? '#ff003c' : p.status===403 ? '#ffaa00' : '#00ff88'
                  }}>
                    HTTP {p.status} {p.note}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
        
        {(result.subdomains?.length>0 || result.dns_subdomains?.length>0) && (
          <div className="card"><h3>🌐 SUBDOMAINS ({(result.subdomains||[]).length + (result.dns_subdomains||[]).length})</h3>
            <div className="tags">
              {(result.subdomains||[]).slice(0,20).map((s,i)=><span key={`crt-${i}`} className="tag">{s}</span>)}
              {(result.dns_subdomains||[]).map((s,i)=><span key={`dns-${i}`} className="tag danger-tag">{s.subdomain} → {s.ip}</span>)}
            </div>
          </div>
        )}
        
        {result.emails_found?.length>0 && (
          <div className="card"><h3>📧 EMAILS FOUND</h3>
            <div className="tags">
              {result.emails_found.map((e,i)=><span key={i} className="tag danger-tag">{e}</span>)}
            </div>
          </div>
        )}
        
        {result.pages?.robots_txt && (
          <div className="card"><h3>🤖 ROBOTS.TXT</h3>
            <div style={{fontSize:'0.72em',color:'rgba(0,220,200,0.5)',whiteSpace:'pre-wrap',fontFamily:'monospace',background:'rgba(0,0,0,0.3)',padding:'10px',borderRadius:'6px',maxHeight:'200px',overflow:'auto'}}>
              {result.pages.robots_txt}
            </div>
            {result.pages.disallowed_paths?.length>0 && (
              <div style={{marginTop:'10px'}}>
                <div className="info-label">DISALLOWED PATHS</div>
                <div className="tags">
                  {result.pages.disallowed_paths.map((d,i)=><span key={i} className="tag danger-tag">{d}</span>)}
                </div>
              </div>
            )}
          </div>
        )}
        
        {result.pages?.sitemap_found && (
          <div className="card"><h3>📍 SITEMAP</h3>
            <div className="info-label">URLS FOUND: {result.pages.sitemap_urls?.length||0}</div>
            {(result.pages.sitemap_urls||[]).slice(0,10).map((u,i)=>(
              <div key={i} style={{fontSize:'0.72em',color:'rgba(0,220,200,0.5)',fontFamily:'monospace',marginTop:'3px'}}>{u}</div>
            ))}
          </div>
        )}
        
        {result.pages?.links_found?.length>0 && (
          <div className="card"><h3>🔗 LINKS FOUND</h3>
            <div style={{maxHeight:'200px',overflow:'auto'}}>
              {result.pages.links_found.map((l,i)=>(
                <div key={i} style={{fontSize:'0.72em',color:'rgba(0,220,200,0.5)',fontFamily:'monospace',marginTop:'2px'}}>{l}</div>
              ))}
            </div>
          </div>
        )}

        {/* VULNERABILITIES — WITH CONFIRMATION FOR DIRECT IP */}
        {result.vulnerabilities?.length > 0 && (
          <>
            {!result.scan_info?.scanner_ip_hidden && !vulnConfirmed ? (
              <div className="card" style={{
                borderColor:'rgba(255,0,60,0.6)',
                background:'rgba(255,0,60,0.05)',
                textAlign:'center',
                padding:'35px 25px'
              }}>
                <h3 style={{color:'#ff003c', fontSize:'1.1em', marginBottom:'15px'}}>
                  ⚠️ CONFIRMATION REQUIRED
                </h3>
                <div style={{
                  background:'rgba(0,0,0,0.4)',
                  border:'1px solid rgba(255,0,60,0.3)',
                  borderRadius:'8px',
                  padding:'18px',
                  margin:'15px 0',
                  textAlign:'left'
                }}>
                  <p style={{color:'#ff6666', fontSize:'0.85em', lineHeight:'1.8'}}>
                    🔴 Connection: <b>DIRECT (IP EXPOSED)</b><br/>
                    🔴 Your IP: <span style={{fontFamily:'monospace', color:'#ff003c'}}>{result.scan_info?.detected_ip || 'Unknown'}</span><br/>
                    🔴 Country: {result.scan_info?.detected_country || 'Unknown'}<br/>
                    <br/>
                    <span style={{color:'#ffaa00'}}>
                      ⚡ {result.vulnerability_count} vulnerabilities detected but hidden.<br/>
                      Displaying them means accepting that your real IP was already logged by the target.
                    </span>
                  </p>
                </div>
                <div style={{display:'flex', gap:'15px', justifyContent:'center', marginTop:'20px', flexWrap:'wrap'}}>
                  <button 
                    onClick={() => setVulnConfirmed(true)}
                    style={{
                      background:'linear-gradient(135deg, rgba(255,0,60,0.2), rgba(255,0,60,0.05))',
                      border:'1px solid #ff003c',
                      color:'#ff003c',
                      padding:'12px 28px',
                      borderRadius:'6px',
                      cursor:'pointer',
                      fontFamily:'Orbitron,monospace',
                      fontSize:'0.78em',
                      letterSpacing:'1px',
                      textShadow:'0 0 10px rgba(255,0,60,0.5)'
                    }}
                  >
                    ⚠ YES, SHOW VULNERABILITIES
                  </button>
                </div>
              </div>
            ) : (
              <div className="card" style={{borderColor:'rgba(255,0,60,0.4)'}}>
                <h3 style={{color:'#ff003c'}}>
                  🛡 VULNERABILITIES FOUND ({result.vulnerability_count})
                  {!result.scan_info?.scanner_ip_hidden && (
                    <span style={{
                      float:'right',
                      fontSize:'0.55em',
                      color:'#ff003c',
                      background:'rgba(255,0,60,0.1)',
                      border:'1px solid rgba(255,0,60,0.3)',
                      padding:'4px 10px',
                      borderRadius:'4px'
                    }}>
                      ⚠ IP EXPOSED
                    </span>
                  )}
                </h3>
                
                {result.critical_count > 0 && (
                  <div style={{marginBottom:'12px',padding:'10px',background:'rgba(255,0,60,0.08)',borderRadius:'6px',border:'1px solid rgba(255,0,60,0.2)'}}>
                    <span style={{color:'#ff003c',fontSize:'0.82em'}}>
                      🔴 {result.critical_count} CRITICAL | 🟠 {result.high_count} HIGH severity issues detected!
                    </span>
                  </div>
                )}
                
                {result.vulnerabilities.map((v,i)=>(
                  <div key={i} className="breach-item" style={{
                    borderLeft: `3px solid ${
                      v.severity==='CRITICAL' ? '#ff003c' : 
                      v.severity==='HIGH' ? '#ff6600' : 
                      v.severity==='MEDIUM' ? '#ffaa00' : 
                      v.severity==='LOW' ? '#00ff88' : '#00ccff'
                    }`,
                    paddingLeft:'12px',
                    marginBottom:'14px'
                  }}>
                    <div className="breach-header">
                      <span className="breach-name" style={{fontSize:'0.85em'}}>
                        {v.severity==='CRITICAL' ? '🔴' : v.severity==='HIGH' ? '🟠' : v.severity==='MEDIUM' ? '🟡' : v.severity==='LOW' ? '🟢' : '🔵'} {v.title}
                      </span>
                      <span className="badge" style={{
                        background: v.severity==='CRITICAL' ? 'rgba(255,0,60,0.16)' : v.severity==='HIGH' ? 'rgba(255,102,0,0.16)' : v.severity==='MEDIUM' ? 'rgba(255,170,0,0.16)' : 'rgba(0,255,136,0.16)',
                        border: `1px solid ${v.severity==='CRITICAL' ? '#ff003c' : v.severity==='HIGH' ? '#ff6600' : v.severity==='MEDIUM' ? '#ffaa00' : '#00ff88'}44`,
                        color: v.severity==='CRITICAL' ? '#ff003c' : v.severity==='HIGH' ? '#ff6600' : v.severity==='MEDIUM' ? '#ffaa00' : '#00ff88'
                      }}>
                        {v.severity}
                      </span>
                    </div>
                    <p style={{fontSize:'0.8em',color:'rgba(255,255,255,0.7)',marginTop:'6px',lineHeight:'1.5'}}>
                      {v.description}
                    </p>
                    <div style={{
                      marginTop:'8px',
                      padding:'8px 12px',
                      background:'rgba(0,220,200,0.05)',
                      borderRadius:'6px',
                      border:'1px solid rgba(0,220,200,0.1)'
                    }}>
                      <span style={{color:'#00ff88',fontSize:'0.75em',fontWeight:'bold'}}>✅ FIX: </span>
                      <span style={{color:'rgba(0,220,200,0.7)',fontSize:'0.75em'}}>{v.remediation}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
        
        {result.vulnerabilities?.length === 0 && result.basic?.is_online && (
          <div className="card safe-card">
            <h3>✅ NO VULNERABILITIES DETECTED</h3>
            <p>Basic security checks passed. No common misconfigurations found.</p>
          </div>
        )}
        </>
      );
    }

    if(tab==='image'){
      const full = result.full || {};
      return(
        <>
        <div className="card"><h3>📁 FILE INFO</h3><InfoGrid data={result.basic}/></div>
        <div className="card"><h3>📱 DEVICE INFO</h3><InfoGrid data={result.device}/></div>
        <div className="card"><h3>📷 CAMERA SETTINGS</h3><InfoGrid data={result.camera}/></div>
        <div className="card"><h3>🕐 DATE & TIME</h3><InfoGrid data={result.datetime}/></div>
        
        {result.location?.location_found && (
          <div className="card"><h3>📍 GPS LOCATION FOUND!</h3>
            <InfoGrid data={{latitude:result.location.latitude,longitude:result.location.longitude}}/>
            {result.location.address && <InfoGrid data={result.location.address}/>}
            <a href={result.location.map_url} target="_blank" rel="noreferrer" className="map-link">📍 VIEW ON MAP</a>
            <a href={result.location.google_maps} target="_blank" rel="noreferrer" className="map-link" style={{marginLeft:'10px'}}>🗺 GOOGLE MAPS</a>
          </div>
        )}
        
        {full.reverse_search?.saucenao?.available && full.reverse_search.saucenao.results?.length > 0 && (
          <div className="card"><h3>🔍 SAUCENAO REVERSE SEARCH</h3>
            {full.reverse_search.saucenao.results.map((res,i)=>(
              <div key={i} className="breach-item">
                <div className="breach-header">
                  <span className="breach-name">⬡ {res.title || 'Unknown Source'}</span>
                  <span className="badge" style={{background:'rgba(0,255,136,0.16)',border:'1px solid #00ff8844',color:'#00ff88'}}>
                    {res.similarity}% Match
                  </span>
                </div>
                <div className="breach-meta">
                  <span>📍 {res.site}</span>
                </div>
                {res.source_url && (
                  <a href={res.source_url} target="_blank" rel="noreferrer" className="map-link" style={{marginTop:'8px',display:'inline-block'}}>
                    🔗 VIEW SOURCE
                  </a>
                )}
              </div>
            ))}
          </div>
        )}
        
        {full.reverse_search?.google_vision?.available && (
          <div className="card"><h3>🔍 GOOGLE VISION MATCHES</h3>
            {full.reverse_search.google_vision.best_guess_labels?.length > 0 && (
              <div style={{marginBottom:'12px'}}>
                <div className="info-label">BEST GUESS</div>
                <div className="tags">
                  {full.reverse_search.google_vision.best_guess_labels.map((l,i)=><span key={i} className="tag">{l}</span>)}
                </div>
              </div>
            )}
            {full.reverse_search.google_vision.pages_with_matching_images?.length > 0 && (
              <div>
                <div className="info-label">PAGES WITH THIS IMAGE</div>
                {full.reverse_search.google_vision.pages_with_matching_images.map((p,i)=>(
                  <div key={i} className="breach-item">
                    <div className="breach-name">🌐 {p.title || 'Unknown Page'}</div>
                    <a href={p.url} target="_blank" rel="noreferrer" className="map-link" style={{fontSize:'0.75em'}}>{p.url}</a>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
        
        {(!full.reverse_search?.saucenao?.available && !full.reverse_search?.google_vision?.available) && (
          <div className="card"><h3>🔍 REVERSE SEARCH</h3>
            <p style={{color:'#ffaa00',fontSize:'0.85em'}}>
              ⚠ API keys not configured. Add SAUCENAO_API_KEY and GOOGLE_VISION_API_KEY to your .env file for actual reverse search results.
            </p>
          </div>
        )}
        
        {full.ocr?.has_text && (
          <div className="card"><h3>📝 OCR TEXT FOUND</h3>
            <div style={{fontSize:'0.82em',color:'#00ffcc',whiteSpace:'pre-wrap',fontFamily:'monospace',background:'rgba(0,0,0,0.3)',padding:'12px',borderRadius:'8px'}}>
              {full.ocr.text}
            </div>
            <div className="info-grid" style={{marginTop:'10px'}}>
              <div className="info-item"><div className="info-label">WORDS</div><div className="info-value">{full.ocr.word_count}</div></div>
            </div>
          </div>
        )}
        
        {full.qr_codes?.found && (
          <div className="card"><h3>📱 QR/BARCODE DETECTED</h3>
            {full.qr_codes.codes.map((code,i)=>(
              <div key={i} className="breach-item">
                <div className="breach-name">{code.type}</div>
                <div style={{fontSize:'0.8em',color:'#00ffcc',wordBreak:'break-all'}}>{code.data}</div>
              </div>
            ))}
          </div>
        )}
        
        {full.ela?.performed && (
          <div className="card" style={{borderColor:full.ela.color+'44'}}>
            <h3 style={{color:full.ela.color}}>🔍 ERROR LEVEL ANALYSIS (ELA)</h3>
            <div className="info-grid">
              <div className="info-item"><div className="info-label">MANIPULATION</div><div className="info-value" style={{color:full.ela.color}}>{full.ela.manipulation_level}</div></div>
              <div className="info-item"><div className="info-label">MEAN DIFF</div><div className="info-value">{full.ela.mean_difference}</div></div>
              <div className="info-item"><div className="info-label">MAX DIFF</div><div className="info-value">{full.ela.max_difference}</div></div>
            </div>
            <p style={{fontSize:'0.72em',color:'rgba(255,255,255,0.4)',marginTop:'8px'}}>{full.ela.note}</p>
          </div>
        )}
        
        {full.hidden && (
          <div className="card" style={{borderColor:full.hidden.risk==='CRITICAL'?'rgba(255,0,60,0.5)':'rgba(0,220,200,0.2)'}}>
            <h3 style={{color:full.hidden.risk==='CRITICAL'?'#ff003c':'#00ccff'}}>
              🕵 HIDDEN CONTENT — {full.hidden.risk}
            </h3>
            <div className="info-grid" style={{marginBottom:'12px'}}>
              <div className="info-item"><div className="info-label">RISK SCORE</div><div className="info-value" style={{color:full.hidden.risk_score>50?'#ff003c':'#00ff88'}}>{full.hidden.risk_score}/100</div></div>
              <div className="info-item"><div className="info-label">STEGANOGRAPHY</div><div className="info-value" style={{color:full.hidden.steganography_detected?'#ff003c':'#00ff88'}}>{full.hidden.steganography_detected?'⚠ DETECTED':'✅ NOT FOUND'}</div></div>
            </div>
            {full.hidden.virus_indicators?.length>0 && (
              <div style={{marginBottom:'12px',padding:'10px',background:'rgba(255,0,60,0.08)',borderRadius:'8px'}}>
                <div className="info-label" style={{color:'#ff003c'}}>🦠 VIRUS INDICATORS!</div>
                {full.hidden.virus_indicators.map((v,i)=><div key={i} style={{fontSize:'0.78em',color:'#ff6666'}}>⚠ {v}</div>)}
              </div>
            )}
            {full.hidden.embedded_files?.length>0 && (
              <div style={{marginBottom:'12px'}}>
                <div className="info-label">📎 EMBEDDED FILES</div>
                {full.hidden.embedded_files.map((f,i)=>(
                  <div key={i} className="breach-item">
                    <span style={{color:f.dangerous?'#ff003c':'#ffaa00'}}>{f.dangerous?'🔴':'🟡'} {f.type}</span>
                  </div>
                ))}
              </div>
            )}
            {full.hidden.hidden_text?.length>0 && (
              <div>
                <div className="info-label">📝 HIDDEN TEXT</div>
                {full.hidden.hidden_text.map((t,i)=>(
                  <div key={i} style={{fontSize:'0.75em',color:'rgba(255,170,0,0.8)',padding:'5px',background:'rgba(0,0,0,0.3)',borderRadius:'4px',marginBottom:'5px',fontFamily:'monospace'}}>{t.slice(0,150)}</div>
                ))}
              </div>
            )}
          </div>
        )}
        
        {full.ai_description?.ai_description && (
          <div className="card ai-card"><h3>🤖 AI CONTENT ANALYSIS</h3>
            <p>{full.ai_description.ai_description}</p>
          </div>
        )}
        
        {result.face && (
          <div className="card">
            <h3>👤 FACE ANALYSIS</h3>
            <div className="info-grid">
              <div className="info-item"><div className="info-label">FACE DETECTED</div><div className="info-value" style={{color:result.face.face_detected?'#00ff88':'#ffaa00'}}>{result.face.face_detected?'✅ YES':'❌ NO'}</div></div>
              <div className="info-item"><div className="info-label">DEEPFAKE</div><div className="info-value">{result.face.deepfake_check?.verdict||'Unknown'}</div></div>
            </div>
          </div>
        )}
        </>
      );
    }

    if(tab==='hash'){
      return(
        <>
        <div className="card"><h3>🔐 HASH INFO</h3>
          <InfoGrid data={{hash:result.hash,length:result.length,type:result.hash_types?.join(', '),algorithm:result.security_info?.algorithm,is_weak:String(result.security_info?.is_weak)}}/>
        </div>
        {result.crack_result?.cracked && (
          <div className="card" style={{borderColor:'rgba(0,255,136,0.35)'}}>
            <h3 style={{color:'#00ff88'}}>🔓 HASH CRACKED!</h3>
            <InfoGrid data={{plaintext:result.crack_result.plaintext,method:result.crack_result.method}}/>
          </div>
        )}
        <div className="card"><h3>⚠ SECURITY ASSESSMENT</h3>
          <p style={{color:result.security_info?.is_weak?'#ff6600':'#00ff88',fontSize:'0.88em',lineHeight:'1.8'}}>{result.security_info?.recommendation}</p>
        </div>
        </>
      );
    }

    if(tab==='log'){
      const s=result.summary||{};
      return(
        <>
        <div className="card"><h3>📊 SUMMARY</h3><InfoGrid data={s}/></div>
        {result.brute_force_ips?.length>0 && (
          <div className="card"><h3>⚠ BRUTE FORCE DETECTED</h3>
            {result.brute_force_ips.map((b,i)=>(
              <div key={i} className="breach-item">
                <div className="breach-name">🚨 {b.ip}</div>
                <div className="breach-meta"><span>Failed: {b.failed_count}</span><span>📍 {b.location?.country}</span></div>
                <span className="tag danger-tag">{b.threat}</span>
              </div>
            ))}
          </div>
        )}
        {result.suspicious_ips?.length>0 && (
          <div className="card"><h3>🚨 SUSPICIOUS IPS</h3>
            {result.suspicious_ips.map((sus,i)=>(
              <div key={i} className="breach-item">
                <div className="breach-name">◉ {sus.ip}</div>
                <div className="breach-meta"><span>📍 {sus.location?.country}</span><span>{sus.location?.isp}</span></div>
                <div className="tags" style={{marginTop:'8px'}}>
                  {sus.attacks?.map((atk,j)=><span key={j} className="tag danger-tag">{atk.replace(/_/g,' ').toUpperCase()}</span>)}
                </div>
              </div>
            ))}
          </div>
        )}
        {result.ai_summary && (<div className="card ai-card"><h3>◈ AI THREAT SUMMARY</h3><p>{result.ai_summary}</p></div>)}
        <div className="card"><h3>📈 TOP ATTACKING IPS</h3>
          <table>
            <thead><tr><th>IP ADDRESS</th><th>REQUESTS</th></tr></thead>
            <tbody>{result.top_ips?.map((ip,i)=>(
              <tr key={i}><td>{ip.ip}</td><td style={{color:'#ff003c'}}>{ip.requests}</td></tr>
            ))}</tbody>
          </table>
        </div>
        </>
      );
    }

    return null;
  }

  return(
    <div className="app">
      <canvas ref={matrixRef} id="matrix-canvas"></canvas>
      <div className="bg-grid"></div>
      <div className="bg-glow-tl"></div>
      <div className="bg-glow-br"></div>

      <div className="header">
        <EyeLogo/>
        <div className="logo-text">
          <span className="logo-eye">EYE</span>
          <span className="logo-on">ON</span>
          <span className="logo-you">YOU</span>
        </div>
        <div className="logo-subtitle">ADVANCED OSINT & CYBER INTELLIGENCE PLATFORM</div>
        <div className="logo-tagline">"WE SEE WHAT YOU DON'T"</div>
        <div className="header-line"></div>
      </div>

      <div className="stats-bar">
        <div className="stat-item">
          <div className="stat-number">{totalScans.toLocaleString()}+</div>
          <div className="stat-label">TOTAL SCANS</div>
        </div>
        <div className="stat-item">
          <div className="stat-number">6</div>
          <div className="stat-label">OSINT TOOLS</div>
        </div>
        <div className="stat-item">
          <div className="stat-number">TOR ●</div>
          <div className="stat-label">DARK WEB</div>
        </div>
        <div className="stat-item">
          <div className="stat-number">AI ◈</div>
          <div className="stat-label">GROQ POWERED</div>
        </div>
      </div>

      <div className="search-box">
        <div className="corner corner-tl"></div>
        <div className="corner corner-tr"></div>
        <div className="corner corner-bl"></div>
        <div className="corner corner-br"></div>

        <div className="search-type">
          {TABS.map(t=>(
            <button key={t.id} className={tab===t.id?'active':''} onClick={()=>setTab(t.id)}>
              <span className="tab-icon">{t.icon}</span>
              <span className="tab-label">{t.label}</span>
            </button>
          ))}
        </div>

        {!isFileTab?(
          <div className="search-input">
            <div style={{flex:1,position:'relative'}}>
              <input
                ref={inputRef}
                type="text"
                placeholder={currentTab?.placeholder}
                value={query}
                onChange={handleInput}
                onKeyPress={e=>e.key==='Enter'&&handleSearch()}
              />
              {tab==='email' && query && (
                <div style={{position:'absolute',right:'16px',top:'50%',transform:'translateY(-50%)',fontFamily:'Orbitron,monospace',fontSize:'0.65em',color:query.includes('@')?'#00ffcc':'#ff003c'}}>
                  {query.includes('@')?'✓ @':'✗ @'}
                </div>
              )}
            </div>
            <button onClick={handleSearch} disabled={loading}>
              {loading?'◌ SCANNING':'◉ SCAN NOW'}
            </button>
          </div>
        ):(
          <div className="file-upload">
            <input type="file" accept={tab==='image'?'image/*':'.log,.txt'} onChange={e=>setFile(e.target.files[0])}/>
            <button onClick={handleSearch} disabled={loading}>
              {loading?'◌ SCANNING':'◉ ANALYZE'}
            </button>
          </div>
        )}

        {validErr && <div className="valid-error">{validErr}</div>}
        <div className="mode-indicator">
          ◎ ACTIVE: {currentTab?.label} SCAN
          {tab==='email'&&' | MUST CONTAIN @'}
          {tab==='ip'&&' | FORMAT: 192.168.1.1'}
        </div>
      </div>

      {error && <div className="error">⚠ {error}</div>}

      {loading && (
        <div className="loading">
          <div className="load-eye-wrapper">
            <div className="load-eye-ring r1"></div>
            <div className="load-eye-ring r2"></div>
            <div className="load-eye-ring r3"></div>
            <div className="load-eye-core">◉</div>
          </div>
          <p className="loading-text">{scanText}</p>
        </div>
      )}

      <div className="results">{renderResult()}</div>

      <div className="footer">
        ◉ EYEONYOU — ADVANCED OSINT & CYBER INTELLIGENCE PLATFORM ◉ FINAL YEAR PROJECT
      </div>
    </div>
  );
}
