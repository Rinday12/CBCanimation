<?php
// ============================================================
// Animasi Perhitungan CBC (Cipher Block Chaining) — Kriptografi
// untuk mahasiswa semester 3. Siap hosting di Vercel (PHP runtime).
// ============================================================

// ---------- Utilitas ----------
function hexToBin(string $hex): string {
    $hex = ltrim($hex, '0x');
    $bits = '';
    foreach (str_split($hex, 2) as $byte) {
        $bits .= str_pad(decbin((int)$byte), 8, '0', STR_PAD_LEFT);
    }
    return $bits;
}
function binToHex(string $bin): string {
    $hex = '';
    for ($i = 0; $i < strlen($bin); $i += 8) {
        $chunk = substr($bin, $i, 8);
        $hex .= str_pad(dechex(bindec($chunk)), 2, '0', STR_PAD_LEFT);
    }
    return $hex;
}
// =====================================================================
// =====================================================================
// KRITOGRAFI BLOK SEDERHANA — BLOK 8 BIT (1 BYTE), non-AES.
// Cocok untuk pengajaran kriptografi dasar: 1 blok = 8 bit = 1 byte.
//
//   E_K(m)  [m, K : 8 bit (0..255)]  -- E_K sebagai black-box
//     C = E_K(m)   (operasi enkripsi blok dengan kunci K)
//     m = D_K(C)   (operasi dekripsi, kebalikan)
//
//   Untuk pembelajaran, E_K diimplementasikan sebagai XOR dengan K
//   (bijektif & reversibel, mudah dipahami).
//   Karena 1 blok = 1 byte, setiap langkah bisa ditulis tangan.
// =====================================================================

// Kunci = kode ASCII 1 huruf (8 bit / 1 byte).
function deriveKeyByte(string $keyWord): int {
    $keyWord = trim($keyWord);
    return $keyWord !== '' ? ord($keyWord[0]) : 0; // kode ASCII huruf pertama
}

// Enkripsi 1 blok 8-bit: C = m XOR K (black-box E_K)
function encryptBlock(int $m, int $K): int {
    return $m ^ $K;
}
// Dekripsi 1 blok 8-bit: m = C XOR K (kebalikan D_K)
function decryptBlock(int $e, int $K): int {
    return $e ^ $K;
}

function hexToBin2(string $hex): string {
    $bits = '';
    foreach (str_split($hex, 2) as $b) {
        $bits .= str_pad(decbin((int)$b), 8, '0', STR_PAD_LEFT);
    }
    return $bits;
}

// ---------- Data form ----------
// BLOK = 8 BIT (1 BYTE) sesuai pengajaran kriptografi dasar
// KEY  : 1 huruf -> kode ASCII (1 byte / 8 bit)
// IV   : 2 digit hex (1 byte), contoh "11" / "00" -> menjadi C_0 (1 blok 8-bit)
// PT   : kalimat bebas -> setiap karakter = 1 blok 8-bit (PKCS7 pad 1 byte)
$keyInput  = trim($_POST['key'] ?? 'R');
$ivInput   = trim($_POST['iv']  ?? '11');
$ptInput   = trim($_POST['pt']  ?? 'universitas ahmad dahlan');

// ---- KEY: 1 huruf -> kode ASCII (1 byte / 8 bit) ----
$K = deriveKeyByte($keyInput);            // 0..255
$keyHex = str_pad(dechex($K), 2, '0', STR_PAD_LEFT); // tampilan 1 byte

// ---- IV: 2 digit hex -> 1 blok 8-bit (C_0) ----
$ivHex = strtolower(preg_replace('/[^0-9a-f]/', '', $ivInput));
$ivHex = substr(str_pad($ivHex, 2, '0'), 0, 2);
if ($ivHex === '') $ivHex = '00';
$IV = hexdec($ivHex); // nilai numerik 0..255

// ---- PLAINTEXT: huruf bebas -> 1 byte per blok (8 bit) ----
// 1 karakter ASCII = 1 byte = 1 blok 8-bit. PKCS7 pad 1 byte di akhir.
$padded = $ptInput . chr(1); // PKCS7: tambah 1 byte bernilai 1 (padLen=1 utk 1 blok)
// Sebenarnya: 1 blok = 1 byte, jadi pad selalu 1 byte (padLen = 1).
// Untuk animasi, batasi maks 6 blok agar tidak terlalu panjang.
$padded = substr($padded, 0, 6);
$blocks = str_split($padded, 1); // 1 blok = 1 karakter
$padShown = chr(1);

// ---------- Hitung CBC (blok 8-bit) ----------
// Konversi helper
function byteToHex(int $b): string { return str_pad(dechex($b), 2, '0', STR_PAD_LEFT); }
function hexToByte(string $h): int { return (int)hexdec($h); }
// XOR 2 byte
function xorByte(int $a, int $b): int { return $a ^ $b; }

// C_i = E_K(P_i XOR C_{i-1}), dengan C_0 = IV (semua 8-bit / 1 byte)
$prev = $IV;
$cipherHex = [];
$interHex  = [];
$steps = [];
foreach ($blocks as $i => $p) {
    $pVal = ord($p); // nilai 8-bit blok plaintext
    // P_i XOR C_{i-1}
    $ixVal = xorByte($pVal, $prev);
    // E_K(xor)
    $cVal = encryptBlock($ixVal, $K);
    $cipherHex[] = byteToHex($cVal);
    $interHex[]  = byteToHex($ixVal);
    $steps[] = [
        'p'    => $p, 'pVal' => $pVal, 'pHex' => byteToHex($pVal),
        'prev' => $prev, 'prevHex' => byteToHex($prev),
        'ix'   => $ixVal, 'ixHex'  => byteToHex($ixVal),
        'c'    => $cVal, 'cHex'  => byteToHex($cVal),
        'K'    => $K,
    ];
    $prev = $cVal;
}
$finalC = $cipherHex;

// ---------- Format tampilan bit ----------
function bitsGroup(string $hex): string {
    $bits = hexToBin2($hex);
    $out = '';
    for ($i = 0; $i < strlen($bits); $i++) {
        if ($i > 0 && $i % 4 === 0) $out .= ' ';
        $out .= $bits[$i];
    }
    return $out;
}
function bitsGroupN(string $bits, int $n): string {
    $out = '';
    for ($i = 0; $i < strlen($bits); $i++) {
        if ($i > 0 && $i % $n === 0) $out .= ' ';
        $out .= $bits[$i];
    }
    return $out;
}

function e($s){ return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
// Tampilkan hex sebagai teks yang bisa dibaca (byte ASCII), atau hex mentah bila bukan printable
function hexToText(string $hex): string {
    $raw = hex2bin($hex);
    $out = '';
    for ($i = 0; $i < strlen($raw); $i++) {
        $c = $raw[$i];
        $o = ord($c);
        if ($o >= 32 && $o <= 126) $out .= $c;
        else $out .= '[' . sprintf('%02x', $o) . ']';
    }
    return $out;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Animasi Perhitungan CBC (Cipher Block Chaining)</title>
<style>
  :root {
    --bg:        #0b1020;
    --panel:     #141a30;
    --panel2:    #1a2140;
    --border:    #2b3660;
    --text:      #e8ecff;
    --muted:     #9aa6d6;
    --accent:    #6d9bff;
    --accent2:   #35e0c0;
    --warn:      #ffd166;
    --cipher:    #ff7b9c;
    --pt:        #4ade80;
    --iv:        #f59e0b;
    --mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: radial-gradient(1200px 800px at 20% -10%, #16204a, var(--bg));
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    line-height: 1.5;
  }
  .wrap { max-width: 1000px; margin: 0 auto; padding: 24px 16px 80px; }

  header h1 { font-size: 26px; margin: 8px 0 4px; letter-spacing: .3px; }
  header p  { color: var(--muted); margin: 0 0 20px; }
  .tag {
    display: inline-block; font-size: 12px; color: var(--accent2);
    border: 1px solid var(--border); border-radius: 999px; padding: 3px 10px;
    background: var(--panel2); letter-spacing: .5px; text-transform: uppercase;
  }

  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px;
    margin-bottom: 18px;
    box-shadow: 0 10px 30px rgba(0,0,0,.35);
  }
  .card h2 { margin: 0 0 12px; font-size: 17px; color: var(--accent); }

  /* ===== CBC DIAGRAM (vertikal, sesuai referensi) ===== */
  .cbcdiagram {
    display:flex; flex-wrap:nowrap; gap:0; margin:6px 0 4px;
    overflow-x:auto; padding-bottom:10px;
  }
  .cbccol {
    display:flex; flex-direction:column; align-items:center;
    min-width:130px; flex:0 0 auto; position:relative;
    padding:0 10px;
  }
  /* kotak */
  .cbx {
    width:130px; border-radius:10px; padding:8px 10px; text-align:center;
    border:1px solid var(--border); background:var(--panel2); position:relative;
    transition:.2s;
  }
  .cbx .cbx-h { font-size:11px; font-weight:700; letter-spacing:.3px; margin-bottom:3px; }
  .cbx .cbx-v { font-family:var(--mono); font-size:11.5px; word-break:break-all; }
  .cbx .cbx-t { font-size:10px; color:var(--muted); margin-top:3px; }
  .cbx .cbx-v2 { font-family:var(--mono); font-size:10px; margin-top:3px; }
  .cbx .cbx-k { color:var(--accent2); font-size:10px; }
  /* warna per peran */
  .cbx.pt  { border-color:var(--pt); }    .cbx.pt .cbx-h{ color:var(--pt); }   .cbx.pt .cbx-v{ color:var(--pt); }
  .cbx.xor { border-color:var(--warn); }  .cbx.xor .cbx-h{ color:var(--warn); }
  .cbx.ct  { border-color:var(--cipher); }.cbx.ct .cbx-h{ color:var(--cipher); }.cbx.ct .cbx-v{ color:var(--cipher); }
  .cbx.enc,.cbx.dec {
    border-color:var(--accent2); background:linear-gradient(135deg,#162040,#1a2f4a);
    cursor:pointer; box-shadow:0 4px 14px rgba(53,224,192,.15);
  }
  .cbx.enc .cbx-h,.cbx.dec .cbx-h { color:var(--accent2); font-size:13px; }
  .cbx.enc:hover,.cbx.dec:hover,.cbx.enc.open,.cbx.dec.open {
    border-color:var(--accent); box-shadow:0 8px 24px rgba(109,155,255,.35);
    transform:translateY(-2px);
  }
  .cbx .detail {
    display:none; margin-top:8px; padding:8px; border-top:1px dashed var(--border);
    font-family:var(--mono); font-size:10px; line-height:1.8; text-align:left; color:var(--text);
    background:rgba(13,18,38,.7); border-radius:0 0 8px 8px;
  }
  .cbx.open .detail { display:block; animation:fade .3s ease; }
  .cbx .detail .lbl { color:var(--accent2); }
  .cbx .hint2 { font-size:9px; color:var(--muted); margin-top:4px; }
  /* panah */
  .cb-arr {
    font-size:14px; color:var(--accent); margin:2px 0; text-align:center;
    width:100%;
  }
  /* chaining antar blok */
  .cbc-chain {
    position:relative; min-width:46px; display:flex; flex-direction:column;
    align-items:center; justify-content:center; flex:0 0 auto;
  }
  .cbc-chain span {
    position:absolute; top:48%; font-size:10px; color:var(--cipher);
    background:var(--panel); padding:1px 6px; border-radius:999px;
    border:1px solid var(--border); letter-spacing:.3px; white-space:nowrap;
  }
  .cbc-dots {
    display:flex; align-items:center; justify-content:center;
    min-width:36px; flex:0 0 auto; font-size:22px; color:var(--accent);
    font-family:var(--mono);
  }
  .cbc-ellipsis-col {
    display:flex; flex-direction:column; align-items:center;
    min-width:100px; flex:0 0 auto; padding:0 8px;
  }
  .cbc-ellipsis-col .cbx { width:100px; }
  @keyframes fade { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:none} }
  @media (max-width:760px){ .cbcdiagram { flex-wrap:wrap; } .cbccol{ margin:8px 0; } }

  /* ===== ALUR LOGIKA (changelog) ===== */
  .changelog { display:flex; flex-direction:column; gap:10px; margin-top:6px; }
  .cl-item { display:flex; gap:12px; align-items:flex-start;
    border:1px solid var(--border); border-radius:10px; padding:10px 14px;
    background:var(--panel2); }
  .cl-item .cl-num {
    font-family:var(--mono); font-size:18px; font-weight:700; color:var(--pt);
    min-width:42px; text-align:center; }
  .cl-item p { margin:0; font-size:13px; color:var(--text); line-height:1.7; }
  .cl-item p b { color:var(--accent2); }

  /* form */
  form { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
  form .full { grid-column: 1 / -1; }
  label { display:block; font-size: 13px; color: var(--muted); margin-bottom: 6px; }
  input {
    width: 100%; padding: 10px 12px; border-radius: 10px;
    border: 1px solid var(--border); background: var(--panel2); color: var(--text);
    font-family: var(--mono); font-size: 14px;
  }
  input:focus { outline: none; border-color: var(--accent); }
  .btn {
    margin-top: 14px; width: 100%; padding: 12px; cursor: pointer;
    border: none; border-radius: 12px; font-size: 15px; font-weight: 600;
    background: linear-gradient(135deg, var(--accent), var(--accent2)); color: #04122b;
  }
  .btn:active { transform: translateY(1px); }
  .hint { font-size: 12px; color: var(--muted); margin-top: 10px; }

  /* diagram blok */
  .flow { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 8px; }
  .node {
    min-width: 92px; padding: 10px 8px; text-align: center; border-radius: 12px;
    border: 1px solid var(--border); background: var(--panel2);
    font-family: var(--mono);
  }
  .node .lbl { font-size: 11px; color: var(--muted); letter-spacing: .4px; margin-bottom: 4px; }
  .node .val { font-size: 13px; word-break: break-all; }
  .node.iv  .val { color: var(--iv); }
  .node.pt  .val { color: var(--pt); }
  .node.cx  .val { color: var(--warn); }
  .node.ct  .val { color: var(--cipher); border-color: var(--cipher); }
  .node.kx  .lbl { color: var(--accent2); }
  .arrow { color: var(--accent); font-size: 20px; align-self: center; }

  /* legend */
  .legend { display:flex; flex-wrap:wrap; gap:12px; margin-top:12px; font-size:12px; color:var(--muted); }
  .legend span { display:inline-flex; align-items:center; gap:6px; }
  .dot { width:10px; height:10px; border-radius:50%; display:inline-block; }

  /* langkah animasi */
  .step {
    display: none;
    border: 1px solid var(--border);
    border-left: 4px solid var(--accent);
    border-radius: 12px;
    background: var(--panel2);
    padding: 16px;
    margin-bottom: 12px;
    opacity: 0;
    transform: translateY(10px);
    transition: opacity .5s ease, transform .5s ease;
  }
  .step.show { display:block; opacity:1; transform: translateY(0); }
  .step .head { font-size: 15px; font-weight: 600; margin-bottom: 8px; }
  .step .head b { color: var(--accent2); }
  .step p.desc { margin: 0 0 12px; color: var(--muted); font-size: 13px; }

  .math {
    background: #0d1226; border:1px solid var(--border); border-radius:10px;
    padding: 12px; font-family: var(--mono); font-size: 13px; overflow-x:auto;
    white-space: pre; color: var(--text);
  }
  .math .k  { color: var(--accent2); }
  .math .p  { color: var(--pt); }
  .math .c  { color: var(--cipher); }
  .math .iv { color: var(--iv); }
  .math .x  { color: var(--warn); }

  /* baris bit warna-warni */
  .bits { font-family: var(--mono); font-size: 13px; letter-spacing: .5px; margin: 4px 0; }
  .bits .b0 { color: var(--muted); }
  .bits .b1 { color: var(--accent2); font-weight: 600; }
  .bits .sep { color: #3a4670; }

  /* tabel hasil */
  table { width:100%; border-collapse: collapse; font-size: 13px; }
  th, td { padding: 10px; text-align:left; border-bottom:1px solid var(--border); font-family: var(--mono); }
  th { color: var(--accent); font-family: inherit; }
  td.c { color: var(--cipher); }

  /* kontrol play */
  .controls { display:flex; gap:10px; margin-top: 8px; }
  .ctrl {
    flex:1; padding:11px; cursor:pointer; border-radius:10px; border:1px solid var(--border);
    background: var(--panel2); color: var(--text); font-weight:600; font-size:14px;
  }
  .ctrl.primary { background: linear-gradient(135deg,var(--accent),var(--accent2)); color:#04122b; border:none; }
  .ctrl:disabled { opacity:.45; cursor:not-allowed; }

  @media (max-width: 720px){ form { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <span class="tag">Kriptografi</span>
    <h1>Animasi Perhitungan CBC — <em>Cipher Block Chaining</em></h1>
    <p>Kriptografi</p>
  </header>

  <!-- ===== INPUT ===== -->
  <div class="card">
    <h2>1 · Masukan (Key, IV, Plaintext)</h2>
    <form method="post">
      <div>
        <label>Key (cukup 1 huruf, contoh: R)</label>
        <input name="key" value="<?= e($keyInput) ?>" maxlength="1" />
      </div>
      <div>
        <label>IV (contoh: 11 / 00 — 1 byte)</label>
        <input name="iv" value="<?= e($ivInput) ?>" />
      </div>
      <div>
        <label>Plaintext (kalimat bebas)</label>
        <input name="pt" value="<?= e($ptInput) ?>" />
      </div>
      <div class="full">
        <button type="submit" class="btn">Hitung &amp; Ulangi Animasi →</button>
        <p class="hint">
          <b>Blok = 8 bit (1 byte)</b> sesuai pengajaran kriptografi dasar.<br>
          <b>Key</b> = cukup <b>1 huruf</b> (mis. <em>R</em>) → kode ASCII menjadi kunci 8‑bit (1 byte).<br>
          <b>IV</b> = 1 byte, contoh <code>11</code> (hex) atau <code>00</code> → menjadi C₀ (1 blok 8‑bit).<br>
          <b>Plaintext</b> = setiap karakter = 1 blok 8‑bit. Maks 6 blok ditampilkan.
        </p>
      </div>
    </form>
  </div>

  <!-- ===== KUNCI & IV (penurunan) ===== -->
  <div class="card">
    <h2>2 · Setup: Kunci &amp; IV (blok 8 bit, TIDAK pakai AES)</h2>
    <div class="math"><span class="k">Key (input)</span> = "<?= e($keyInput) ?>"  <span style="color:var(--muted)">(1 huruf)</span><br>
<span class="k">Kunci K</span>   = <span class="k"><?= $keyHex ?></span>  <span style="color:var(--muted)">→ kode ASCII "<?= e($keyInput[0] ?? '') ?>" = <?= $K ?> (biner <?= e(b8($K)) ?>)</span><br>
<span style="color:var(--iv)">IV</span> = "<?= e($ivInput) ?>"  →  <span class="iv"><?= $ivHex ?></span>  <span style="color:var(--muted)">= C₀ (1 blok 8‑bit, nilai <?= $IV ?>)</span></div>

    <h3 style="margin:14px 0 6px;color:var(--accent2);font-size:14px">Kriptografi Blok 8‑bit yang Dipakai (bukan AES)</h3>
    <p style="color:var(--muted);font-size:13px;margin:0 0 10px">
      Setiap blok <b>8 bit (1 byte)</b> dienkripsi sebagai <b>black-box E_K</b>:
    </p>
    <div class="math">C = E_K(m)   [m, K : 8 bit]
<span style="color:var(--cipher)">→ keluaran C (8 bit) = Ciphertext blok</span>
<span style="color:var(--muted);font-size:12px">D_K(C) = m  (kebalikan E_K)</span></div>
    <p class="hint">Kunci K 8 bit = kode ASCII dari 1 huruf input (mis. "R" = 82 = 01010010). E_K &amp; D_K berupa kotak hitam — fokus pembelajaran ada pada aturan chaining CBC.</p>
  </div>

  <!-- ===== POLA KOTAK INTERAKTIF ===== -->
  <!-- ===== CBC DIAGRAM: ENCRYPTION ===== -->
  <div class="card">
    <h2>3 · Diagram CBC — Enkripsi</h2>
    <p class="hint" style="margin:0 0 14px">
      Klik/tekan <b>kotak Encrypt</b> untuk melihat kunci K yang dipakai.
      Chaining: <b>Cᵢ</b> keluar dari blok ke‑n masuk ke blok ke‑(n+1) sebagai Cᵢ₋₁.
    </p>
    <div class="cbcdiagram" id="enc">
      <?php
        // helper format array byte -> hex
        if (!function_exists('fmtArr2')) {
          function fmtArr2(array $a): string {
            $o=''; foreach($a as $x){ $o.=($o!==' '?' ':'').sprintf('%02x',$x); } return $o;
          }
        }
        $isLastEnc = count($steps) - 1;
        // helper: nilai 8-bit -> biner 8 digit
        function b8(int $v): string { return str_pad(decbin($v), 8, '0', STR_PAD_LEFT); }
      ?>
      <?php foreach ($steps as $i => $s):
        $n = $i + 1;
        $K = $s['K'];
      ?>
      <div class="cbccol" data-stage="<?= $n ?>">
        <!-- P_i di atas -->
        <div class="cbx pt">
          <div class="cbx-h">P_<?= $n ?></div>
          <div class="cbx-v"><?= e($s['p']) ?> <span style="color:var(--muted)">= <?= $s['pHex'] ?></span></div>
          <div class="cbx-t"><?= e(b8($s['pVal'])) ?></div>
        </div>
        <!-- panah ke bawah -->
        <div class="cb-arr">↓</div>
        <!-- XOR node -->
        <div class="cbx xor">
          <div class="cbx-h">⊕</div>
          <?php if ($i === 0): ?>
            <div class="cbx-v">P₁ ⊕ IV</div>
            <div class="cbx-t">IV = <?= e($ivHex) ?> (=<?= $IV ?>)</div>
          <?php else: ?>
            <div class="cbx-v">P_<?= $n ?> ⊕ C_<?= $n ?></div>
            <div class="cbx-t">C_<?= $n ?> = <?= e($s['prevHex']) ?> (=<?= $s['prev'] ?>)</div>
          <?php endif; ?>
          <div class="cbx-v2" style="color:var(--warn)">XOR = <?= e($s['ixHex']) ?> (<?= e(b8($s['ix'])) ?>)</div>
        </div>
        <div class="cb-arr">↓</div>
        <!-- Encrypt (kotak besar, bisa klik) -->
        <div class="cbx enc" onclick="toggleBox(this)" tabindex="0">
          <div class="cbx-h">Encrypt <span class="cbx-k">K</span></div>
          <div class="cbx-v">E_K(XOR)</div>
          <div class="detail">
            <div class="lbl">K = <?= $K ?> (<?= e(b8($K)) ?>)</div>
            <div style="color:var(--cipher);margin-top:4px">C_<?= $n ?> = <?= $s['cHex'] ?></div>
          </div>
          <div class="hint2">klik untuk lihat kunci</div>
        </div>
        <div class="cb-arr">↓</div>
        <!-- C_i di bawah -->
        <div class="cbx ct">
          <div class="cbx-h">C_<?= $n ?></div>
          <div class="cbx-v"><?= e($s['cHex']) ?></div>
          <?php if ($i < $isLastEnc): ?>
            <div class="cbx-t">→ chaining ke blok <?= $n+1 ?></div>
          <?php else: ?>
            <div class="cbx-t">ciphertext akhir</div>
          <?php endif; ?>
        </div>
      </div>
      <?php if ($i < $isLastEnc): ?>
      <div class="cbc-chain">C_<?= $n ?><span>chaining →</span>C_<?= $n+1 ?></div>
      <?php endif; ?>
      <?php endforeach; ?>
      <?php if ($isLastEnc > 0): ?>
      <div class="cbc-dots">⋯</div>
      <div class="cbc-ellipsis-col">
        <div class="cbx pt"><div class="cbx-h">P_n</div><div class="cbx-t">blok terakhir</div></div>
        <div class="cb-arr">↓</div>
        <div class="cbx enc"><div class="cbx-h">Encrypt K</div></div>
        <div class="cb-arr">↓</div>
        <div class="cbx ct"><div class="cbx-h">C_n</div><div class="cbx-t">= <span style="color:var(--cipher)"><?= e($cipherHex[count($cipherHex)-1]) ?></span></div></div>
      </div>
      <?php endif; ?>
    </div>
  </div>

  <!-- ===== CBC DIAGRAM: DEKRIPSI ===== -->
  <div class="card">
    <h2>4 · Diagram CBC — Dekripsi</h2>
    <p class="hint" style="margin:0 0 14px">
      Kebalikan dari enkripsi: Cᵢ di‑dekripsi dulu, baru di‑XOR dengan Cᵢ₋₁
      (untuk blok pertama di‑XOR dengan IV). Klik kotak <b>Decrypt</b> untuk melihat langkah baliknya.
    </p>
    <div class="cbcdiagram" id="dec">
      <?php foreach ($steps as $i => $s):
        $n = $i + 1;
        $K=$s['K'];
      ?>
      <div class="cbccol" data-stage="<?= $n ?>">
        <!-- C_i di atas -->
        <div class="cbx ct">
          <div class="cbx-h">C_<?= $n ?></div>
          <div class="cbx-v"><?= e($s['cHex']) ?></div>
        </div>
        <div class="cb-arr">↓</div>
        <!-- Decrypt -->
        <div class="cbx dec" onclick="toggleBox(this)" tabindex="0">
          <div class="cbx-h">Decrypt <span class="cbx-k">K</span></div>
          <div class="cbx-v">D_K(C_<?= $n ?>)</div>
          <div class="detail">
            <div style="color:var(--muted)">Output D_K: <?= e(b8($s['c'])) ?></div>
            <div style="color:var(--muted)">K = <?= $K ?> (<?= e(b8($K)) ?>)</div>
          </div>
          <div class="hint2">klik untuk rincian</div>
        </div>
        <div class="cb-arr">↓</div>
        <!-- XOR -->
        <div class="cbx xor">
          <div class="cbx-h">⊕</div>
          <?php if ($i === 0): ?>
            <div class="cbx-v">D_K(C₁) ⊕ IV</div>
            <div class="cbx-t">IV = <?= e($ivHex) ?> (<?= $IV ?>)</div>
          <?php else: ?>
            <div class="cbx-v">D_K(C_<?= $n ?>) ⊕ C_<?= $n ?></div>
            <div class="cbx-t">C_<?= $n ?> = <?= e($s['prevHex']) ?></div>
          <?php endif; ?>
        </div>
        <div class="cb-arr">↓</div>
        <!-- P_i di bawah -->
        <div class="cbx pt">
          <div class="cbx-h">P_<?= $n ?></div>
          <div class="cbx-v"><?= e($s['p']) ?> <span style="color:var(--muted)">= <?= $s['pHex'] ?></span></div>
          <div class="cbx-t"><?= e(b8($s['pVal'])) ?></div>
        </div>
      </div>
      <?php if ($i < $isLastEnc): ?>
      <div class="cbc-chain">C_<?= $n ?><span>chaining →</span>C_<?= $n+1 ?></div>
      <?php endif; ?>
      <?php endforeach; ?>
      <?php if ($isLastEnc > 0): ?>
      <div class="cbc-dots">⋯</div>
      <div class="cbc-ellipsis-col">
        <div class="cbx ct"><div class="cbx-h">C_n</div></div>
        <div class="cb-arr">↓</div>
        <div class="cbx dec"><div class="cbx-h">Decrypt K</div></div>
        <div class="cb-arr">↓</div>
        <div class="cbx pt"><div class="cbx-h">P_n</div></div>
      </div>
      <?php endif; ?>
    </div>
  </div>

  <!-- Legend (shared) -->
  <div class="card">
    <div class="legend">
      <span><i class="dot" style="background:var(--pt)"></i> Plaintext (P)</span>
      <span><i class="dot" style="background:var(--iv)"></i> IV / C sebelumnya</span>
      <span><i class="dot" style="background:var(--warn)"></i> Hasil XOR</span>
      <span><i class="dot" style="background:var(--cipher)"></i> Ciphertext (C)</span>
      <span><i class="dot" style="background:var(--accent2)"></i> Kotak Encrypt/Decrypt (klik = rincian)</span>
    </div>
  </div>

  <!-- ===== ALUR LOGIKA ENKRIPSI (penjelasan teks) ===== -->
  <div class="card">
    <h2>5 · Alur Logika Enkripsi</h2>
    <p style="color:var(--text);font-size:13.5px;line-height:1.8;margin:0 0 12px">
      Proses selalu berjalan <b>dari kiri ke kanan</b> (P₁ sampai Pₙ).
      Perhatikan panah pada diagram:
    </p>
    <div class="changelog">
      <div class="cl-item"><span class="cl-num">P₁</span>
        <p><b>Blok pertama:</b> P₁ di‑XOR dengan <b>IV</b> (karena belum ada blok sebelumnya).
        Hasil XOR dimasukkan ke fungsi <b>Encrypt(K)</b>. Keluarnya <b>C₁</b>.</p></div>
      <div class="cl-item"><span class="cl-num">P₂</span>
        <p><b>Blok kedua:</b> P₂ di‑XOR dengan <b>C₁</b> (ciphertext blok sebelumnya, <b>bukan IV lagi</b>).
        Hasil XOR di‑Encrypt(K) dengan kunci yang sama → <b>C₂</b>.</p></div>
      <div class="cl-item"><span class="cl-num">P₃</span>
        <p><b>Blok ketiga dst.:</b> Lakukan hal yang sama. P₃ di‑XOR dengan <b>C₂</b>, lalu di‑Encrypt(K), hasilnya <b>C₃</b>.
        Pola ini berulang sampai Pₙ → Cₙ.</p></div>
    </div>
    <div class="math" style="margin-top:12px">
<span class="k">P₁ ⊕ IV → E_K → C₁</span>
<span class="k">P₂ ⊕ C₁ → E_K → C₂</span>
<span class="k">P₃ ⊕ C₂ → E_K → C₃</span>
<span class="k"> … </span>
<span class="k">Pₙ ⊕ Cₙ₋₁ → E_K → Cₙ</span></div>
  </div>

  <!-- ===== LANGKAH (JUDUL) ===== -->
  <div class="card">
    <h2>6 · Langkah Perhitungan (Animasi)</h2>
    <div class="controls">
      <button id="play"   class="ctrl primary">▶ Putar Animasi</button>
      <button id="showAll" class="ctrl">Tampilkan Semua</button>
      <button id="reset"   class="ctrl">Reset</button>
    </div>
  </div>

  <?php
    // helper 8-bit -> biner 8 digit
    if (!function_exists('b8')) {
      function b8(int $v): string { return str_pad(decbin($v), 8, '0', STR_PAD_LEFT); }
    }
  ?>
  <?php foreach ($steps as $i => $s):
    $n = $i + 1;
    $isIv = ($i === 0);
    $pVal = $s['pVal']; $prev = $s['prev']; $ix = $s['ix']; $cVal = $s['c'];
    $K = $s['K'];
  ?>
  <!-- Langkah A: XOR -->
  <div class="step" data-step="<?= $i * 2 ?>">
    <div class="head">Langkah <?= $n ?>a · <b>P_<?= $n ?> ("<?= e($s['p']) ?>") XOR <?= $isIv ? 'IV (C₀)' : 'C_'.($n-1) ?></b></div>
    <p class="desc">
      Setiap blok = <b>8 bit (1 byte)</b>.
      <?= $isIv
        ? 'Blok pertama: P₁ di‑XOR dengan <b>IV</b> (karena belum ada blok sebelumnya). IV berperan sebagai "C₀".'
        : 'Blok ke‑'.($n).': P_'.($n).' di‑XOR dengan <b>C_'.($n-1).'</b> (ciphertext dari blok sebelumnya, <b>bukan IV lagi</b>). Inilah "chaining" pada CBC.'
      ?>
      Operasi XOR per‑bit: 1⊕0=1, 0⊕1=1, 1⊕1=0, 0⊕0=0.
    </p>
    <div class="math"><span class="x">P_<?= $n ?></span>   <?= b8($pVal) ?>  (<?= $pVal ?>)
<span class="<?= $isIv ? 'iv' : 'c' ?>"><?= $isIv ? 'C₀(IV)' : 'C_'.($n-1) ?></span>  <?= b8($prev) ?>  (<?= $prev ?>)
<span class="x">─────</span>    <span class="x">(XOR)</span>
<span class="x">XOR  </span> <?= b8($ix) ?>  → 0x<?= $s['ixHex'] ?>  (<?= $ix ?>)</div>
  </div>

  <!-- Langkah B: Enkripsi blok 8-bit -->
  <div class="step" data-step="<?= $i * 2 + 1 ?>">
    <div class="head">Langkah <?= $n ?>b · <b>C_<?= $n ?> = E_K(XOR)</b> — Kriptografi Blok 8-bit</div>
    <p class="desc">
      Hasil XOR dienkripsi dengan <b>black-box E_K</b> (kriptografi blok 8-bit, bukan AES).
      <?= $i < count($steps)-1
        ? 'Ciphertext C_'.($n).' ini menjadi input chaining untuk blok berikutnya.'
        : 'Inilah ciphertext terakhir (blok akhir).' ?>
    </p>
    <div class="math">input m  = <span class="x"><?= $ix ?> (<?= b8($ix) ?>)</span>
Kunci K  = <span class="k"><?= $K ?> (<?= b8($K) ?>)</span>

C = E_K(m)  = <span class="c"><?= $cVal ?> (<?= b8($cVal) ?>)</span>

<span class="c">→ C_<?= $n ?> = <?= $s['cHex'] ?></span>  (8 bit)</div>
  </div>
  <?php endforeach; ?>

  <!-- ===== HASIL ===== -->
  <div class="card" id="result" style="display:none">
    <h2>7 · Hasil Ciphertext</h2>
    <table>
      <thead><tr><th>Blok</th><th>P (char)</th><th>P (8-bit)</th><th>XOR</th><th>Ciphertext C</th></tr></thead>
      <tbody>
        <?php foreach ($steps as $i => $s): ?>
        <tr>
          <td><?= $i+1 ?></td>
          <td><?= e($s['p']) ?></td>
          <td><?= e($s['pHex']) ?></td>
          <td><?= e($s['ixHex']) ?></td>
          <td class="c"><?= e($s['cHex']) ?></td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
    <p class="hint" style="margin-top:12px">
      Urutan ciphertext: <span style="color:var(--cipher);font-family:var(--mono)">
      <?= implode(' ', $cipherHex) ?></span>
    </p>
  </div>

</div>

<script>
  // ================== KOTAK INTERAKTIF ==================
  // Klik/tekan kotak untuk membuka rincian 2 langkah internalnya.
  // Kotak XOR & C berisi <div class="detail"> yang tersembunyi;
  // P & IV tidak punya detail sehingga klik hanya toggle class 'open' (tanpa efek visual besar).
  function toggleBox(el){
    el.classList.toggle('open');
    // kunci: bila ada kotak lain terbuka di grup yang sama, tutup yang lain
    // (opsional; di sini kita biarkan banyak bisa terbuka sekaligus agar bisa dibandingkan)
  }
  // Aksesibilitas: Enter/Space membuka
  document.addEventListener('keydown', function(ev){
    if ((ev.key === 'Enter' || ev.key === ' ') && ev.target.classList && ev.target.classList.contains('box')) {
      ev.preventDefault();
      toggleBox(ev.target);
    }
  });

  // ================== ANIMASI ==================
  const steps   = Array.from(document.querySelectorAll('.step'));
  const resultEl = document.getElementById('result');
  const playBtn   = document.getElementById('play');
  const showAllBtn= document.getElementById('showAll');
  const resetBtn  = document.getElementById('reset');
  let timer = null;

  function hideAll(){
    steps.forEach(s => { s.classList.remove('show'); });
    resultEl.style.display = 'none';
  }
  function showOne(el){
    el.classList.add('show');
    el.scrollIntoView({ behavior:'smooth', block:'center' });
  }
  function stop(){ if(timer){ clearInterval(timer); timer=null; playBtn.disabled=false; } }

  function play(){
    stop();
    hideAll();
    const seq = steps.slice();
    let i = 0;
    playBtn.disabled = true;
    timer = setInterval(() => {
      if (i < seq.length){ showOne(seq[i]); i++; }
      else {
        stop();
        resultEl.style.display = 'block';
        resultEl.scrollIntoView({behavior:'smooth', block:'start'});
      }
    }, 1900);
  }
  function showAll(){
    stop();
    steps.forEach(s => s.classList.add('show'));
    resultEl.style.display = 'block';
  }
  function resetAll(){
    stop();
    hideAll();
    playBtn.disabled = false;
  }

  playBtn.addEventListener('click', play);
  showAllBtn.addEventListener('click', showAll);
  resetBtn.addEventListener('click', resetAll);

  // Kalau sudah POST, tampilkan "semua" sekalian; kalau GET, tampilkan langkah 1 sebagai contoh
  <?php if ($_SERVER['REQUEST_METHOD'] === 'POST') { echo 'showAll();'; } else { echo "steps[0].classList.add('show');"; } ?>
</script>
</body>
</html>
