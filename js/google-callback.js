/* Página de retorno do login do Google (google-callback.html).
 * O Google devolve o token no fragmento da URL (#access_token=...). Esta página, que é do próprio site, só
 * repassa o resultado para a aba aberta (BroadcastChannel, mesma origem), apaga o fragmento e fecha a janela.
 * O token nunca é gravado em disco nem mandado para nenhum servidor. */
(() => {
  const p = new URLSearchParams(location.hash.replace(/^#/, "") || location.search.replace(/^\?/, ""));
  const message = {
    type: "token",
    access_token: p.get("access_token") || "",
    expires_in: p.get("expires_in") || "",
    state: p.get("state") || "",
    error: p.get("error") || ""
  };
  history.replaceState(null, "", location.pathname); // o token sai da barra de endereço e do histórico
  const channel = new BroadcastChannel("arca-google");
  channel.postMessage(message);
  setTimeout(() => {
    channel.close();
    window.close();
    const msg = document.getElementById("msg");
    if (msg) msg.textContent = message.error ? "Conexão cancelada. Pode fechar esta janela." : "Conectado. Pode fechar esta janela.";
  }, 300);
})();
