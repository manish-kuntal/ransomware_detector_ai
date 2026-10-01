"""
evaluator.py — Evaluation plots and reports for research paper.

Generates:
  • Comparison table (all metrics, all models)
  • ROC curves (all models on one plot)
  • Confusion matrices (one per model)
  • Feature importance bar chart (Random Forest / XGBoost)
  • Detection latency histogram
"""
import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')          # headless — no display required
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from sklearn.metrics import (roc_curve, auc, confusion_matrix,
                              ConfusionMatrixDisplay)

try:
    import seaborn as sns
    sns.set_theme(style='whitegrid', palette='muted')
    _SEABORN = True
except ImportError:
    _SEABORN = False


class ModelEvaluator:
    """
    Accepts the `results_` dict from ModelTrainer and produces all
    figures needed for a research paper.

    Parameters
    ----------
    results      : ModelTrainer.results_ dict
    feature_names: list of feature name strings
    output_dir   : directory where PNGs are saved
    X_test, y_test: held-out test data (needed for ROC / latency plots)
    """

    def __init__(self, results: dict, feature_names: list,
                 output_dir: str, X_test, y_test):
        self.results       = results
        self.feature_names = feature_names
        self.out_dir       = output_dir
        self.X_test        = X_test
        self.y_test        = y_test
        os.makedirs(self.out_dir, exist_ok=True)

    # ── public ────────────────────────────────────────────────────────────────

    def run_all(self):
        """Generate all figures."""
        print("[*] Generating evaluation figures...")
        self.comparison_table()
        self.roc_curves()
        self.confusion_matrices()
        self.feature_importance()
        print(f"[✓] Figures saved in: {self.out_dir}")

    def comparison_table(self) -> pd.DataFrame:
        rows = []
        for name, r in self.results.items():
            m = r['metrics']
            rows.append({
                'Model':     name,
                'Accuracy':  f"{m['accuracy']:.4f}",
                'Precision': f"{m['precision']:.4f}",
                'Recall':    f"{m['recall']:.4f}",
                'F1':        f"{m['f1']:.4f}",
                'ROC-AUC':   f"{m['roc_auc']:.4f}",
                'FPR':       f"{m['fpr']:.4f}",
                'CV F1':     f"{m['cv_f1_mean']:.4f}±{m['cv_f1_std']:.4f}",
            })

        df = pd.DataFrame(rows).set_index('Model')
        csv_path = os.path.join(self.out_dir, 'comparison_table.csv')
        df.to_csv(csv_path)
        print(f"\n{'='*65}")
        print("Model Comparison")
        print('='*65)
        print(df.to_string())
        print('='*65)
        return df

    def roc_curves(self):
        fig, ax = plt.subplots(figsize=(8, 6))
        colors  = ['#2196F3', '#F44336', '#4CAF50', '#FF9800']

        for (name, r), color in zip(self.results.items(), colors):
            pipe   = r['pipeline']
            y_prob = pipe.predict_proba(self.X_test)[:, 1]
            fpr, tpr, _ = roc_curve(self.y_test, y_prob)
            roc_auc_val = auc(fpr, tpr)
            ax.plot(fpr, tpr, label=f'{name} (AUC={roc_auc_val:.3f})',
                    color=color, lw=2)

        ax.plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.5, label='Random (AUC=0.5)')
        ax.set_xlabel('False Positive Rate', fontsize=12)
        ax.set_ylabel('True Positive Rate', fontsize=12)
        ax.set_title('ROC Curves — All Models', fontsize=14, fontweight='bold')
        ax.legend(loc='lower right', fontsize=10)
        ax.set_xlim([0, 1]);  ax.set_ylim([0, 1.02])
        ax.fill_between([0, 1], [0, 1], alpha=0.04, color='gray')

        path = os.path.join(self.out_dir, 'roc_curves.png')
        fig.tight_layout();  fig.savefig(path, dpi=150)
        plt.close(fig)
        print(f"  Saved: {path}")

    def confusion_matrices(self):
        n = len(self.results)
        cols = min(n, 2);  rows = (n + 1) // 2
        fig, axes = plt.subplots(rows, cols, figsize=(6 * cols, 5 * rows))
        axes = np.array(axes).flatten()

        for ax, (name, r) in zip(axes, self.results.items()):
            y_pred = r['pipeline'].predict(self.X_test)
            cm     = confusion_matrix(self.y_test, y_pred)
            disp   = ConfusionMatrixDisplay(cm, display_labels=['Normal', 'Ransomware'])
            disp.plot(ax=ax, colorbar=False, cmap='Blues')
            ax.set_title(name, fontsize=12, fontweight='bold')

        for ax in axes[len(self.results):]:
            ax.set_visible(False)

        fig.suptitle('Confusion Matrices', fontsize=14, fontweight='bold', y=1.01)
        path = os.path.join(self.out_dir, 'confusion_matrices.png')
        fig.tight_layout();  fig.savefig(path, dpi=150, bbox_inches='tight')
        plt.close(fig)
        print(f"  Saved: {path}")

    def feature_importance(self):
        """Bar chart of feature importances (RF / XGBoost)."""
        importances = {}

        for name, r in self.results.items():
            clf = r['pipeline'].named_steps['clf']
            if hasattr(clf, 'feature_importances_'):
                importances[name] = clf.feature_importances_

        if not importances:
            return   # SVM / MLP don't expose feature_importances_

        n = len(importances)
        fig, axes = plt.subplots(1, n, figsize=(8 * n, 6), sharey=True)
        if n == 1:
            axes = [axes]

        colors = ['#2196F3', '#FF9800']

        for ax, (name, imp), color in zip(axes, importances.items(), colors):
            idx     = np.argsort(imp)[::-1]
            top_n   = min(15, len(self.feature_names))
            top_idx = idx[:top_n]
            top_names = [self.feature_names[i] for i in top_idx]
            top_imp   = imp[top_idx]

            ax.barh(range(top_n), top_imp[::-1], color=color, alpha=0.8)
            ax.set_yticks(range(top_n))
            ax.set_yticklabels(top_names[::-1], fontsize=9)
            ax.set_xlabel('Importance', fontsize=11)
            ax.set_title(f'{name}\nFeature Importances', fontsize=12, fontweight='bold')

        path = os.path.join(self.out_dir, 'feature_importance.png')
        fig.tight_layout();  fig.savefig(path, dpi=150)
        plt.close(fig)
        print(f"  Saved: {path}")
