document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initTabs();
    initSliders();
});

// GLOBAL STATE FOR DYNAMIC PERSISTENCE
const state = {
    rsa: {
        private_key: "",
        public_key: ""
    },
    signature: {
        private_key: "",
        public_key: "",
        signature: ""
    },
    charts: {
        vigenere: null,
        frequency: null,
        birthday: null
    }
};

// ==========================================
// 1. NAVIGATION & TABS SYSTEM
// ==========================================
function initNavigation() {
    const navItems = document.querySelectorAll(".nav-item");
    const sections = document.querySelectorAll(".page-section");

    navItems.forEach(item => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const targetId = item.getAttribute("data-target");

            navItems.forEach(nav => nav.classList.remove("active"));
            sections.forEach(sec => sec.classList.remove("active"));

            item.classList.add("active");
            document.getElementById(targetId).classList.add("active");
        });
    });
}

function initTabs() {
    const tabButtons = document.querySelectorAll(".tab-button");

    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const container = btn.closest(".tab-container");
            const tabButtonsInGroup = container.querySelectorAll(".tab-button");
            const tabContents = container.querySelectorAll(".tab-content");
            const targetTabId = btn.getAttribute("data-tab");

            tabButtonsInGroup.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));

            btn.classList.add("active");
            document.getElementById(targetTabId).classList.add("active");
        });
    });
}

function initSliders() {
    // Caesar Shift Slider
    const caesarShift = document.getElementById("caesar-shift");
    const caesarShiftVal = document.getElementById("caesar-shift-val");
    if (caesarShift && caesarShiftVal) {
        caesarShift.addEventListener("input", () => {
            caesarShiftVal.textContent = caesarShift.value;
        });
    }

    // Birthday Paradox Slider
    const bdayPeople = document.getElementById("birthday-people");
    const bdayPeopleVal = document.getElementById("birthday-people-val");
    if (bdayPeople && bdayPeopleVal) {
        bdayPeople.addEventListener("input", () => {
            bdayPeopleVal.textContent = bdayPeople.value;
        });
    }
}

// Helper to make AJAX API POST calls
async function callApi(endpoint, payload) {
    try {
        const response = await fetch(`/api/${endpoint}`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });
        if (!response.ok) {
            throw new Error(`Server returned HTTP ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        alert(`API Error: ${error.message}`);
        return { success: false, error: error.message };
    }
}

// ==========================================
// 2. MODUL 1: KRIPTOGRAFI KLASIK
// ==========================================
async function runCaesar(action) {
    const text = document.getElementById("caesar-text").value;
    const shift = document.getElementById("caesar-shift").value;
    const bfText = document.getElementById("caesar-bf-text").value;

    if (action === "brute_force") {
        const res = await callApi("caesar", { action, text: bfText });
        if (res.success) {
            const tbody = document.querySelector("#caesar-bf-table tbody");
            tbody.innerHTML = "";
            res.result.forEach(row => {
                const tr = document.createElement("tr");
                tr.innerHTML = `<td><strong>Key ${row.key}</strong></td><td><code>${row.decrypted}</code></td>`;
                tbody.appendChild(tr);
            });
            document.getElementById("caesar-bf-container").style.display = "block";
        }
    } else {
        const res = await callApi("caesar", { action, text, shift });
        if (res.success) {
            document.getElementById("caesar-result").textContent = res.result;
            document.getElementById("caesar-result-container").style.display = "block";
        }
    }
}

async function runVigenere(action) {
    const text = document.getElementById("vigenere-text").value;
    const key = document.getElementById("vigenere-key").value;
    const analText = document.getElementById("vigenere-anal-text").value;

    if (action === "analyze") {
        const res = await callApi("vigenere", { action, text: analText });
        if (res.success) {
            document.getElementById("vigenere-ioc-val").textContent = res.ioc.toFixed(5);
            document.getElementById("vigenere-anal-container").style.display = "block";

            // Render Chart.js estimation
            const labels = res.kasiski.map(r => `Panjang ${r.key_len}`);
            const data = res.kasiski.map(r => r.score);

            if (state.charts.vigenere) {
                state.charts.vigenere.destroy();
            }

            const ctx = document.getElementById("vigenere-chart").getContext("2d");
            state.charts.vigenere = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Rata-rata IoC',
                        data: data,
                        backgroundColor: 'rgba(59, 130, 246, 0.6)',
                        borderColor: '#3b82f6',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            grid: { color: '#27272a' },
                            ticks: { color: '#a1a1aa' }
                        },
                        x: {
                            grid: { color: '#27272a' },
                            ticks: { color: '#a1a1aa' }
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }
    } else {
        if (!key) {
            alert("Kunci tidak boleh kosong!");
            return;
        }
        const res = await callApi("vigenere", { action, text, key });
        if (res.success) {
            document.getElementById("vigenere-result").textContent = res.result;
            document.getElementById("vigenere-result-container").style.display = "block";
        }
    }
}

async function runPlayfair(action) {
    const text = document.getElementById("playfair-text").value;
    const key = document.getElementById("playfair-key").value;

    if (action === "matrix") {
        const res = await callApi("playfair", { action, key });
        if (res.success) {
            renderPlayfairMatrix(res.matrix);
        }
    } else {
        if (!key) {
            alert("Kunci tidak boleh kosong!");
            return;
        }
        // Run matrix display update first
        await runPlayfair("matrix");
        
        const res = await callApi("playfair", { action, text, key });
        if (res.success) {
            document.getElementById("playfair-result").textContent = res.result;
            document.getElementById("playfair-result-container").style.display = "block";
        }
    }
}

function renderPlayfairMatrix(matrix) {
    const container = document.getElementById("playfair-matrix-container");
    let html = `<table class="playfair-matrix-table">`;
    for (let r = 0; r < 5; r++) {
        html += `<tr>`;
        for (let c = 0; c < 5; c++) {
            html += `<td>${matrix[r][c]}</td>`;
        }
        html += `</tr>`;
    }
    html += `</table>`;
    container.innerHTML = html;
}

// ==========================================
// 3. MODUL 2: KRIPTOGRAFI SIMETRIS
// ==========================================
async function runSymmetric(algo, action) {
    if (algo === "des_compare") {
        const password = document.getElementById("des-password").value;
        const text = document.getElementById("des-plaintext").value;
        const iv = document.getElementById("des-iv").value;
        
        const res = await callApi("symmetric", { algo, text, password, iv });
        if (res.success) {
            document.getElementById("des-key-hex").textContent = res.des_key;
            document.getElementById("des-cipher-hex").textContent = res.des_ciphertext;
            document.getElementById("des-time-val").textContent = res.des_time.toFixed(4);
            
            document.getElementById("des3-key-hex").textContent = res.des3_key;
            document.getElementById("des3-cipher-hex").textContent = res.des3_ciphertext;
            document.getElementById("des3-time-val").textContent = res.des3_time.toFixed(4);
            
            document.getElementById("des-compare-results").style.display = "block";
        }
    } else {
        const password = document.getElementById("aes-password").value;
        const plaintext = document.getElementById("aes-plaintext").value;
        const iv = document.getElementById("aes-iv").value;
        const nonce = document.getElementById("aes-nonce").value;
        const ciphertext = document.getElementById("aes-ciphertext").value;
        
        const textParam = action === "encrypt" ? plaintext : ciphertext;
        const res = await callApi("symmetric", { algo, action, text: textParam, password, iv, nonce });
        
        if (res.success) {
            if (action === "encrypt") {
                document.getElementById("aes-ciphertext").value = res.result;
                document.getElementById("aes-key-out").textContent = res.key_hex;
                document.getElementById("aes-plaintext-out").textContent = "-";
            } else {
                document.getElementById("aes-plaintext-out").textContent = res.result;
            }
            document.getElementById("aes-result-container").style.display = "block";
        }
    }
}

// ==========================================
// 4. MODUL 3: KRIPTOGRAFI ASIMETRIS
// ==========================================
async function runAsymmetric(algo, action) {
    if (algo === "rsa") {
        if (action === "generate") {
            const res = await callApi("asymmetric", { algo, action });
            if (res.success) {
                state.rsa.private_key = res.private_key;
                state.rsa.public_key = res.public_key;
                document.getElementById("rsa-pub").value = res.public_key;
                document.getElementById("rsa-priv").value = res.private_key;
            }
        } else if (action === "encrypt") {
            const text = document.getElementById("rsa-text").value;
            const pub_key = document.getElementById("rsa-pub").value;
            if (!pub_key) {
                alert("Generate/Masukkan Kunci Publik terlebih dahulu!");
                return;
            }
            const res = await callApi("asymmetric", { algo, action, text, public_key: pub_key });
            if (res.success) {
                document.getElementById("rsa-output").value = res.result;
                document.getElementById("rsa-text").value = res.result; // Set for easy decryption
                document.getElementById("rsa-result-container").style.display = "block";
            }
        } else if (action === "decrypt") {
            const text = document.getElementById("rsa-text").value;
            const priv_key = document.getElementById("rsa-priv").value;
            if (!priv_key) {
                alert("Generate/Masukkan Kunci Privat terlebih dahulu!");
                return;
            }
            const res = await callApi("asymmetric", { algo, action, text, private_key: priv_key });
            if (res.success) {
                document.getElementById("rsa-output").value = res.result;
                document.getElementById("rsa-result-container").style.display = "block";
            }
        }
    } else if (algo === "dh") {
        const dh_type = document.getElementById("dh-scale").value;
        const res = await callApi("asymmetric", { algo, dh_type });
        if (res.success) {
            document.getElementById("dh-alice-priv").textContent = res.alice_priv;
            document.getElementById("dh-bob-priv").textContent = res.bob_priv;
            document.getElementById("dh-alice-pub").textContent = res.alice_pub;
            document.getElementById("dh-bob-pub").textContent = res.bob_pub;
            
            document.getElementById("dh-shared-secret").textContent = res.shared_secret;
            document.getElementById("dh-shared-secret-bob").textContent = res.shared_secret;
            document.getElementById("dh-aes-key").textContent = res.aes_key;
            
            document.getElementById("dh-results").style.display = "block";
            document.getElementById("dh-secret-results").style.display = "block";
        }
    }
}

// ==========================================
// 5. MODUL 4: FUNGSI HASH & MAC
// ==========================================
async function runHash(action) {
    if (action === "hashes") {
        const text = document.getElementById("hash-text").value;
        const res = await callApi("hash", { action, text });
        if (res.success) {
            const tbody = document.querySelector("#hash-results-table tbody");
            tbody.innerHTML = "";
            res.result.forEach(row => {
                const tr = document.createElement("tr");
                tr.innerHTML = `<td><strong>${row.algo}</strong></td><td>${row.bits}</td><td><code style="font-size:0.75rem; word-break:break-all;">${row.hash}</code></td>`;
                tbody.appendChild(tr);
            });
            document.getElementById("hash-table-container").style.display = "block";
        }
    } else if (action === "avalanche") {
        const text1 = document.getElementById("av-text1").value;
        const text2 = document.getElementById("av-text2").value;
        const res = await callApi("hash", { action, text1, text2 });
        if (res.success) {
            document.getElementById("av-hash1").textContent = res.hash1;
            document.getElementById("av-hash2").textContent = res.hash2;
            document.getElementById("av-summary").textContent = `Kedua teks berbeda 1 karakter, namun hasil hash SHA-256 berbeda ${res.differences} dari ${res.hash1.length} karakter hex (~${res.percentage.toFixed(1)}% perbedaan).`;
            document.getElementById("av-results-container").style.display = "block";
        }
    }
}

async function runHMAC(action) {
    if (action === "generate") {
        const text = document.getElementById("hmac-msg").value;
        const key = document.getElementById("hmac-key").value;
        const res = await callApi("hmac", { action, text, key });
        if (res.success) {
            document.getElementById("hmac-signature-out").textContent = res.result;
            document.getElementById("hmac-v-sig").value = res.result; // Auto set for verification
            document.getElementById("hmac-gen-container").style.display = "block";
        }
    } else if (action === "verify") {
        const text = document.getElementById("hmac-v-msg").value;
        const key = document.getElementById("hmac-key").value;
        const signature = document.getElementById("hmac-v-sig").value;
        const res = await callApi("hmac", { action, text, key, signature });
        
        if (res.success) {
            const outBox = document.getElementById("hmac-verify-container");
            const outText = document.getElementById("hmac-verify-result");
            
            if (res.valid) {
                outBox.style.background = "#022c22";
                outBox.style.borderColor = "#064e3b";
                outBox.style.color = "#34d399";
                outText.innerHTML = `<strong>✔ VERIFIKASI SUKSES</strong><br>Integritas pesan terjamin. Pesan belum mengalami modifikasi dan berasal dari pengirim asli.`;
            } else {
                outBox.style.background = "#450a0a";
                outBox.style.borderColor = "#7f1d1d";
                outBox.style.color = "#f87171";
                outText.innerHTML = `<strong>❌ VERIFIKASI GAGAL</strong><br>Pesan telah dimodifikasi atau kunci rahasia salah! Integritas pesan rusak.`;
            }
            outBox.style.display = "block";
        }
    }
}

// ==========================================
// 6. MODUL 5: TANDA TANGAN DIGITAL
// ==========================================
async function runSignature(action) {
    const algo = document.getElementById("sig-algo").value;
    
    if (action === "generate_keys") {
        const res = await callApi("signature", { action, algo });
        if (res.success) {
            state.signature.private_key = res.private_key;
            state.signature.public_key = res.public_key;
            document.getElementById("sig-pub").value = res.public_key;
            document.getElementById("sig-priv").value = res.private_key;
        }
    } else if (action === "sign") {
        const text = document.getElementById("sig-doc").value;
        const priv = document.getElementById("sig-priv").value;
        if (!priv) {
            alert("Silakan generate kunci baru terlebih dahulu!");
            return;
        }
        const res = await callApi("signature", { action, algo, text, private_key: priv });
        if (res.success) {
            state.signature.signature = res.result;
            document.getElementById("sig-v-doc").value = text;
            document.getElementById("sig-v-val").value = res.result;
        }
    } else if (action === "verify") {
        const text = document.getElementById("sig-v-doc").value;
        const sig = document.getElementById("sig-v-val").value;
        const pub = document.getElementById("sig-pub").value;
        
        if (!sig || !pub) {
            alert("Pastikan kunci publik dan signature terisi!");
            return;
        }
        
        const res = await callApi("signature", { action, algo, text, signature: sig, public_key: pub });
        if (res.success) {
            const outBox = document.getElementById("sig-results-container");
            const outText = document.getElementById("sig-verify-result");
            
            if (res.valid) {
                outBox.style.background = "#022c22";
                outBox.style.borderColor = "#064e3b";
                outBox.style.color = "#34d399";
                outText.innerHTML = `✔ [VERIFIKASI SUKSES] Keaslian Terjamin!<br>Dokumen terbukti valid, berasal dari pemegang kunci privat asli, dan isi dokumen sama sekali tidak diubah sejak ditandatangani.`;
            } else {
                outBox.style.background = "#450a0a";
                outBox.style.borderColor = "#7f1d1d";
                outBox.style.color = "#f87171";
                outText.innerHTML = `❌ [VERIFIKASI GAGAL] Dokumen Palsu / Dimanipulasi!<br>Tanda tangan tidak cocok. Dokumen telah dimodifikasi atau tanda tangan dibuat dengan kunci privat yang tidak sesuai.`;
            }
            outBox.style.display = "block";
        }
    }
}

// ==========================================
// 7. MODUL 6: SIMULASI SERANGAN
// ==========================================
async function runAttacks(action) {
    if (action === "frequency") {
        const text = document.getElementById("freq-text").value;
        const res = await callApi("attacks", { attack: "frequency", text });
        if (res.success) {
            // Save decryption options
            document.getElementById("freq-best-key").textContent = res.best_key;
            document.getElementById("freq-best-score").textContent = res.best_score.toFixed(4);
            document.getElementById("freq-plaintext-out").textContent = res.best_plaintext;
            document.getElementById("freq-decrypt-btn").style.display = "block";
            
            // Plot frequency Comparison using Chart.js
            const labels = res.frequencies.map(f => f.letter);
            const cipherFreqs = res.frequencies.map(f => f.ciphertext);
            const englishFreqs = res.frequencies.map(f => f.english);
            
            if (state.charts.frequency) {
                state.charts.frequency.destroy();
            }
            
            document.getElementById("freq-chart-container").style.display = "block";
            const ctx = document.getElementById("freq-chart").getContext("2d");
            state.charts.frequency = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Ciphertext',
                            data: cipherFreqs,
                            backgroundColor: 'rgba(239, 68, 68, 0.6)',
                            borderColor: '#ef4444',
                            borderWidth: 1
                        },
                        {
                            label: 'English Standard',
                            data: englishFreqs,
                            backgroundColor: 'rgba(59, 130, 246, 0.6)',
                            borderColor: '#3b82f6',
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            grid: { color: '#27272a' },
                            ticks: { color: '#a1a1aa' }
                        },
                        x: {
                            grid: { color: '#27272a' },
                            ticks: { color: '#a1a1aa' }
                        }
                    }
                }
            });
        }
    } else if (action === "auto_decrypt") {
        document.getElementById("freq-dec-result").style.display = "block";
    } else if (action === "birthday_calc") {
        const people = document.getElementById("birthday-people").value;
        const res = await callApi("attacks", { attack: "birthday_calc", people });
        if (res.success) {
            document.getElementById("birthday-prob-out").textContent = `${res.probability.toFixed(2)}%`;
            
            // Plot Birthday Paradox Line Curve for 1-100 people
            const xLabels = Array.from({length: 100}, (_, i) => i + 1);
            const yData = [];
            
            // Calculate standard probabilities client-side
            let p_no_collision = 1.0;
            for (let i = 1; i <= 100; i++) {
                p_no_collision *= (365 - i + 1) / 365;
                yData.push((1.0 - p_no_collision) * 100);
            }
            
            if (state.charts.birthday) {
                state.charts.birthday.destroy();
            }
            
            const ctx = document.getElementById("birthday-chart").getContext("2d");
            state.charts.birthday = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: xLabels,
                    datasets: [{
                        label: 'Probabilitas Collision (%)',
                        data: yData,
                        borderColor: '#10b981',
                        borderWidth: 2,
                        fill: false,
                        pointRadius: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            grid: { color: '#27272a' },
                            ticks: { color: '#a1a1aa' }
                        },
                        x: {
                            grid: { color: '#27272a' },
                            ticks: { color: '#a1a1aa', stepSize: 10 }
                        }
                    },
                    plugins: {
                        // Drawing static indicator at current selected people
                        annotation: {
                            // Note: We can skip plugins since a simple line is already clean.
                        }
                    }
                }
            });
        }
    } else if (action === "birthday_collision") {
        const bits = document.getElementById("birthday-bits").value;
        const res = await callApi("attacks", { attack: "birthday_collision", bits });
        if (res.success) {
            document.getElementById("coll-expected").textContent = Math.round(res.expected);
            if (res.found) {
                document.getElementById("coll-attempts").textContent = res.attempts;
                document.getElementById("coll-hash").textContent = res.hash;
                document.getElementById("coll-in1").textContent = res.input1;
                document.getElementById("coll-in2").textContent = res.input2;
                document.getElementById("coll-success-box").style.display = "block";
            } else {
                document.getElementById("coll-success-box").style.display = "none";
            }
            document.getElementById("birthday-collision-out").style.display = "block";
        }
    }
}
