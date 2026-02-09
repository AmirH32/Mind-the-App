import pandas as pd
import os
import sys
import numpy as np
import joblib

from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import sklearn as sklearn
import seaborn as sns

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from apk_discovery_tool.utils.config import CSV_FILE, MODEL_FILE


def train():
    try:
        df = pd.read_csv(filepath_or_buffer=CSV_FILE)
    except FileNotFoundError:
        print("Error: CSV file not found.")
        return

    # Drop rows where 'label' column is empty
    df = df.dropna(subset=["label"])

    # Define Features (X) and Target (y)
    # Drop the columns that are not features
    cols_to_drop = ["apk_name", "package_name", "label", "risk_score_prediction"]

    # Ensure the columns exist
    existing_drop_cols = [c for c in cols_to_drop if c in df.columns]
    X = df.drop(columns=existing_drop_cols)
    y = df["label"].astype(int)

    # Split Data (80% Training, 20% Testing)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=50
    )

    # Search space for hyperparameter tuning
    search_space = {
        "n_estimators": [100, 200, 300],  # Try different amounts of trees
        "max_depth": [None, 10, 20],  # Try different tree heights
        "min_samples_split": [2, 5, 10],  # Try different split requirements
    }

    print(f"Scoring metrics: {sklearn.metrics.SCORERS.keys()}")

    # This will train many versions of your model to find the best one
    grid_search = GridSearchCV(
        estimator=RandomForestClassifier(random_state=42),
        param_grid=search_space,
        cv=5,  # 5-fold cross-validation
        scoring="f1",  # Optimise for the F1-score (balance of precision/recall)
        n_jobs=-1,  # Use all CPU cores to speed up the process
    )

    print("Running Grid Search... this may take a few minutes.")
    grid_search.fit(X_train, y_train)

    clf = grid_search.best_estimator_
    print(f"Best parameters found: {grid_search.best_params_}")

    y_pred = clf.predict(X_test)

    print("\n" + "=" * 30)
    print("MODEL PERFORMANCE")
    print("=" * 30)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.2f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Dual-Use"]))

    # Feature Importance, which features were most important
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]

    print("\nTop 5 Most Important Indicators:")
    for f in range(5):
        if f < len(X.columns):
            print(f"{f + 1}. {X.columns[indices[f]]} ({importances[indices[f]]:.4f})")

    joblib.dump(clf, MODEL_FILE)
    print(f"\nModel saved to {MODEL_FILE}")

    # Generate the Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)

    # Plot it nicely using Seaborn
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Benign", "Dual-Use"],
        yticklabels=["Benign", "Dual-Use"],
    )
    plt.ylabel("Actual Label")
    plt.xlabel("Predicted Label")
    plt.title("Confusion Matrix")

    # Save the plot
    plt.savefig("/home/malan/Documents/files/confusion_matrix.png")


if __name__ == "__main__":
    train()
