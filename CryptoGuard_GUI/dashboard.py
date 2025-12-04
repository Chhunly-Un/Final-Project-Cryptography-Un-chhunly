# dashboard.py
import matplotlib
matplotlib.use('Agg')  # non-GUI backend (we'll export PNG)
import matplotlib.pyplot as plt
from pathlib import Path
from threat_engine import overall_risk_score

OUTPUT_DIR = Path.home() / ".crypto_guard_plus"
OUTPUT_DIR.mkdir(exist_ok=True)

def compute_risk(rsa_ok, aes_ok, pw_entropy):
    checks = {"rsa_ok": rsa_ok, "aes_ok": aes_ok, "pw_entropy": pw_entropy}
    score = overall_risk_score(checks)
    return score

def export_risk_plot(score, out_path=None):
    if out_path is None:
        out_path = OUTPUT_DIR / "risk_plot.png"
    fig, ax = plt.subplots(figsize=(6, 2.5))
    ax.barh([0], [100-score], height=0.6, label='Security (higher better)')
    ax.barh([0], [score], left=[100-score], height=0.6, color='red', label='Risk')
    ax.set_xlim(0, 100)
    ax.set_yticks([])
    ax.set_xlabel('Percent')
    ax.set_title(f'Risk Score: {score}/100 (higher = worse)')
    ax.legend(loc='upper right')
    plt.tight_layout()
    fig.savefig(str(out_path))
    plt.close(fig)
    return out_path
