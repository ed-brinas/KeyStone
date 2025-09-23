
async function api(url, method="GET", body=null) {
  const headers = {"Content-Type":"application/json"};
  const opts = {method, headers, credentials:"include"};
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  if (!res.ok) {
    let msg = await res.text();
    try { const j = JSON.parse(msg); alert(j.error || msg); } catch(e){ alert(msg); }
    throw new Error(msg);
  }
  if (res.headers.get("content-type")?.includes("application/pdf")) {
    const blob = await res.blob();
    const urlb = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = urlb; a.download = "summary.pdf"; a.click();
    return null;
  }
  return await res.json();
}
