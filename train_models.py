"""
train_models.py — Train and evaluate all ML models.

Usage:
  python train_models.py                            # uses default dataset
  python train_models.py --dataset data/datasets/dataset_synthetic.csv
  python train_models.py --evaluate                 # also generate evaluation plots
  python train_models.py --dataset ... --evaluate --plots-dir results/
"""
import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import DATASET_DIR, MODELS_DIR, LOGS_DIR, FEATURE_NAMES
from src.models.trainer   import ModelTrainer
from src.models.evaluator import ModelEvaluator


def main():
    parser = argparse.ArgumentParser(description='Train ransomware detection models')
    parser.add_argument('--dataset',   type=str, default=None,
                        help='Path to dataset CSV (default: data/datasets/dataset_synthetic.csv)')
    parser.add_argument('--evaluate',  action='store_true',
                        help='Generate evaluation plots after training')
    parser.add_argument('--plots-dir', type=str, default=None,
                        help='Directory for evaluation plots (default: results/)')
    parser.add_argument('--test-size', type=float, default=0.20)
    parser.add_argument('--cv-folds',  type=int,   default=5)
    parser.add_argument('--seed',      type=int,   default=42)
    args = parser.parse_args()

    # ── Resolve dataset path ──────────────────────────────────────────────────
    dataset_path = args.dataset
    if dataset_path is None:
        # Try to find a dataset automatically
        for fname in ['dataset_synthetic.csv', 'dataset_simulation.csv',
                      'behavioral_dataset.csv']:
            candidate = os.path.join(DATASET_DIR, fname)
            if os.path.exists(candidate):
                dataset_path = candidate
                break

    if dataset_path is None or not os.path.exists(dataset_path):
        print("[ERROR] No dataset found. Generate one first:")
        print("        python generate_dataset.py --mode synthetic --n 300")
        sys.exit(1)

    print(f"[*] Dataset: {dataset_path}")

    # ── Train ─────────────────────────────────────────────────────────────────
    trainer = ModelTrainer(
        dataset_path = dataset_path,
        models_dir   = MODELS_DIR,
        test_size    = args.test_size,
        random_state = args.seed,
    )
    trainer.load_data()
    results = trainer.train(cv_folds=args.cv_folds)
    trainer.save_all()

    # ── Summary table ─────────────────────────────────────────────────────────
    df = trainer.results_dataframe()
    table_path = os.path.join(LOGS_DIR, 'model_comparison.csv')
    df.to_csv(table_path)
    print(f"\n[✓] Comparison table saved: {table_path}")

    # ── Evaluation plots (optional) ───────────────────────────────────────────
    if args.evaluate:
        plots_dir = args.plots_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 'results'
        )
        evaluator = ModelEvaluator(
            results       = results,
            feature_names = FEATURE_NAMES,
            output_dir    = plots_dir,
            X_test        = trainer.X_test,
            y_test        = trainer.y_test,
        )
        evaluator.run_all()

    print("\n[✓] Done.  Next step:")
    print("    python main.py --watch /path/to/folder   ← real-time detection")
    print("    python dashboard/app.py                  ← web dashboard")


if __name__ == '__main__':
    main()
