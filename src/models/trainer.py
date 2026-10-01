"""
trainer.py — Trains four ML models for ransomware detection.

Models:
  1. Random Forest   (sklearn)
  2. XGBoost         (xgboost)
  3. SVM / RBF       (sklearn)
  4. Neural Network  (sklearn MLPClassifier)

Each model is wrapped in a Pipeline with StandardScaler for feature normalisation.
"""
import os
import pickle
import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
from sklearn.ensemble        import RandomForestClassifier
from sklearn.svm             import SVC
from sklearn.neural_network  import MLPClassifier
from sklearn.preprocessing   import StandardScaler
from sklearn.pipeline        import Pipeline
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics         import (accuracy_score, precision_score,
                                     recall_score, f1_score, roc_auc_score,
                                     confusion_matrix, classification_report)

try:
    from xgboost import XGBClassifier
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False
    print("[WARN] xgboost not installed. Install with: pip install xgboost")


# ─── Model definitions ────────────────────────────────────────────────────────

def _build_models(random_state: int = 42) -> dict:
    models = {
        'RandomForest': Pipeline([
            ('scaler', StandardScaler()),
            ('clf', RandomForestClassifier(
                n_estimators=200,
                max_depth=None,
                min_samples_split=2,
                class_weight='balanced',
                random_state=random_state,
                n_jobs=-1,
            )),
        ]),
        'SVM': Pipeline([
            ('scaler', StandardScaler()),
            ('clf', SVC(
                kernel='rbf',
                C=10.0,
                gamma='scale',
                probability=True,
                class_weight='balanced',
                random_state=random_state,
            )),
        ]),
        'NeuralNetwork': Pipeline([
            ('scaler', StandardScaler()),
            ('clf', MLPClassifier(
                hidden_layer_sizes=(128, 64, 32),
                activation='relu',
                solver='adam',
                max_iter=500,
                early_stopping=True,
                validation_fraction=0.1,
                random_state=random_state,
            )),
        ]),
    }

    if XGB_AVAILABLE:
        models['XGBoost'] = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', XGBClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=6,
                subsample=0.8,
                colsample_bytree=0.8,
                use_label_encoder=False,
                eval_metric='logloss',
                random_state=random_state,
                n_jobs=-1,
            )),
        ])

    return models


# ─── Trainer class ────────────────────────────────────────────────────────────

class ModelTrainer:
    """
    Loads a dataset CSV, trains all models, evaluates them,
    and saves the best one.

    Parameters
    ----------
    dataset_path  : path to CSV with FEATURE_NAMES columns + 'label'
    models_dir    : where to save trained models
    test_size     : fraction held out for final evaluation
    random_state  : reproducibility seed
    """

    def __init__(self, dataset_path: str, models_dir: str,
                 test_size: float = 0.20, random_state: int = 42):
        self.dataset_path = dataset_path
        self.models_dir   = models_dir
        self.test_size    = test_size
        self.rs           = random_state
        os.makedirs(self.models_dir, exist_ok=True)

        self.results_     = {}   # filled by train()
        self.best_model_  = None
        self.best_name_   = None

    # ── public ────────────────────────────────────────────────────────────────

    def load_data(self):
        df = pd.read_csv(self.dataset_path)
        X  = df.drop('label', axis=1).values
        y  = df['label'].values
        self.X_train, self.X_test, self.y_train, self.y_test = \
            train_test_split(X, y, test_size=self.test_size,
                             random_state=self.rs, stratify=y)
        print(f"[*] Dataset loaded: {len(df)} samples | "
              f"train={len(self.X_train)}, test={len(self.X_test)}")
        return self

    def train(self, cv_folds: int = 5) -> dict:
        """Train all models, perform cross-validation, return results dict."""
        models = _build_models(self.rs)
        cv     = StratifiedKFold(n_splits=cv_folds, shuffle=True,
                                  random_state=self.rs)

        print(f"\n[*] Training {len(models)} models with {cv_folds}-fold CV...\n")

        best_f1 = -1
        for name, pipe in models.items():
            print(f"  ── {name} ──")

            # Cross-validation on training set
            cv_scores = cross_val_score(pipe, self.X_train, self.y_train,
                                        cv=cv, scoring='f1', n_jobs=-1)
            print(f"     CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

            # Fit on full training set
            pipe.fit(self.X_train, self.y_train)

            # Evaluate on held-out test set
            y_pred  = pipe.predict(self.X_test)
            y_prob  = pipe.predict_proba(self.X_test)[:, 1]

            metrics = self._compute_metrics(self.y_test, y_pred, y_prob)
            metrics['cv_f1_mean'] = cv_scores.mean()
            metrics['cv_f1_std']  = cv_scores.std()

            self.results_[name] = {'metrics': metrics, 'pipeline': pipe}

            self._print_metrics(name, metrics)

            # Track best model by F1
            if metrics['f1'] > best_f1:
                best_f1          = metrics['f1']
                self.best_model_ = pipe
                self.best_name_  = name

        print(f"\n[✓] Best model: {self.best_name_}  (F1={best_f1:.4f})")
        return self.results_

    def save_all(self):
        """Persist all trained pipelines to disk."""
        for name, r in self.results_.items():
            path = os.path.join(self.models_dir, f'{name.lower()}.pkl')
            with open(path, 'wb') as f:
                pickle.dump(r['pipeline'], f)
            print(f"  Saved: {path}")

        # Save best model separately for real-time detector
        best_path = os.path.join(self.models_dir, 'best_model.pkl')
        with open(best_path, 'wb') as f:
            pickle.dump({'name': self.best_name_, 'pipeline': self.best_model_}, f)
        print(f"  Best model saved: {best_path}")

    def results_dataframe(self) -> pd.DataFrame:
        """Return a tidy DataFrame of metrics for all models."""
        rows = []
        for name, r in self.results_.items():
            row = {'Model': name}
            row.update(r['metrics'])
            rows.append(row)
        return pd.DataFrame(rows).set_index('Model')

    # ── private ───────────────────────────────────────────────────────────────

    @staticmethod
    def _compute_metrics(y_true, y_pred, y_prob) -> dict:
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        return {
            'accuracy':  accuracy_score(y_true, y_pred),
            'precision': precision_score(y_true, y_pred, zero_division=0),
            'recall':    recall_score(y_true, y_pred, zero_division=0),
            'f1':        f1_score(y_true, y_pred, zero_division=0),
            'roc_auc':   roc_auc_score(y_true, y_prob),
            'fpr':       fpr,
            'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
        }

    @staticmethod
    def _print_metrics(name: str, m: dict):
        print(f"     Accuracy : {m['accuracy']:.4f}")
        print(f"     Precision: {m['precision']:.4f}")
        print(f"     Recall   : {m['recall']:.4f}")
        print(f"     F1       : {m['f1']:.4f}")
        print(f"     ROC-AUC  : {m['roc_auc']:.4f}")
        print(f"     FPR      : {m['fpr']:.4f}")
        print()
