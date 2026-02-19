#!/usr/bin/env python3
"""train ml classifiers for network intrusion detection"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, classification_report,
                             roc_curve, auc)


def load_data(benign_path, attack_path):
    """load and combine benign and attack datasets"""
    print(f"[*] loading benign data from {benign_path}")
    benign = pd.read_csv(benign_path)

    print(f"[*] loading attack data from {attack_path}")
    attack = pd.read_csv(attack_path)

    data = pd.concat([benign, attack], ignore_index=True)
    print(f"[*] combined dataset: {len(data)} rows ({len(benign)} benign, {len(attack)} attack)")
    return data


def preprocess(data):
    """clean and prepare data for training"""
    print("[*] preprocessing data")

    # handle missing values - fill numeric with median, categorical with mode
    for col in data.columns:
        if data[col].dtype in ['float64', 'int64']:
            data[col] = data[col].fillna(data[col].median())
        else:
            data[col] = data[col].fillna(data[col].mode().iloc[0] if not data[col].mode().empty else 'unknown')

    # encode categorical columns
    label_encoders = {}
    categorical_cols = data.select_dtypes(include=['object']).columns.tolist()

    # separate the target label from features
    if 'label' in categorical_cols:
        categorical_cols.remove('label')

    for col in categorical_cols:
        le = LabelEncoder()
        data[col] = le.fit_transform(data[col].astype(str))
        label_encoders[col] = le
        print(f"  [+] encoded {col}: {len(le.classes_)} categories")

    # encode the target variable
    label_map = {'benign': 0, 'attack': 1}
    data['label'] = data['label'].map(label_map)

    # separate features and target
    X = data.drop('label', axis=1)
    y = data['label']

    # scale features
    scaler = StandardScaler()
    feature_names = X.columns.tolist()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y, scaler, label_encoders, feature_names


def train_and_evaluate(X_train, X_test, y_train, y_test, feature_names, output_dir):
    """train both classifiers and evaluate their performance"""
    results = {}

    models = {
        'random_forest': RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        ),
        'gradient_boosting': GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42
        )
    }

    best_model = None
    best_f1 = 0

    for name, model in models.items():
        print(f"\n[*] training {name}")
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        cm = confusion_matrix(y_test, y_pred)

        print(f"  accuracy:  {acc:.4f}")
        print(f"  precision: {prec:.4f}")
        print(f"  recall:    {rec:.4f}")
        print(f"  f1 score:  {f1:.4f}")

        results[name] = {
            'accuracy': float(acc),
            'precision': float(prec),
            'recall': float(rec),
            'f1_score': float(f1),
            'confusion_matrix': cm.tolist(),
            'classification_report': classification_report(y_test, y_pred, target_names=['benign', 'attack'])
        }

        # plot confusion matrix
        fig, ax = plt.subplots(figsize=(6, 5))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                    xticklabels=['benign', 'attack'],
                    yticklabels=['benign', 'attack'])
        ax.set_xlabel('predicted')
        ax.set_ylabel('actual')
        ax.set_title(f'{name} - confusion matrix')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{name}_confusion_matrix.png'), dpi=100)
        plt.close()

        # plot roc curve
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        roc_auc = auc(fpr, tpr)
        results[name]['auc'] = float(roc_auc)

        fig, ax = plt.subplots(figsize=(6, 5))
        ax.plot(fpr, tpr, label=f'AUC = {roc_auc:.3f}')
        ax.plot([0, 1], [0, 1], 'k--', alpha=0.5)
        ax.set_xlabel('false positive rate')
        ax.set_ylabel('true positive rate')
        ax.set_title(f'{name} - roc curve')
        ax.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{name}_roc_curve.png'), dpi=100)
        plt.close()

        # track best model by f1 score
        if f1 > best_f1:
            best_f1 = f1
            best_model = (name, model)

        # feature importance for tree-based models
        if hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            indices = np.argsort(importances)[::-1][:10]

            fig, ax = plt.subplots(figsize=(8, 5))
            ax.barh(range(len(indices)), importances[indices])
            ax.set_yticks(range(len(indices)))
            ax.set_yticklabels([feature_names[i] for i in indices])
            ax.set_xlabel('importance')
            ax.set_title(f'{name} - top feature importances')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{name}_feature_importance.png'), dpi=100)
            plt.close()

            results[name]['top_features'] = [
                {'feature': feature_names[i], 'importance': float(importances[i])}
                for i in indices
            ]

    return results, best_model


def generate_report(results, output_dir):
    """write training results to a markdown report"""
    report_path = os.path.join(output_dir, 'training_report.md')

    with open(report_path, 'w') as f:
        f.write("# ml-based intrusion detection - training report\n\n")
        f.write(f"generated: {datetime.now().isoformat()}\n\n")

        for name, metrics in results.items():
            f.write(f"## {name.replace('_', ' ')}\n\n")
            f.write(f"| metric | value |\n")
            f.write(f"|--------|-------|\n")
            f.write(f"| accuracy | {metrics['accuracy']:.4f} |\n")
            f.write(f"| precision | {metrics['precision']:.4f} |\n")
            f.write(f"| recall | {metrics['recall']:.4f} |\n")
            f.write(f"| f1 score | {metrics['f1_score']:.4f} |\n")
            f.write(f"| auc | {metrics.get('auc', 'n/a'):.4f} |\n\n")

            f.write("### confusion matrix\n\n")
            cm = metrics['confusion_matrix']
            f.write("|  | predicted benign | predicted attack |\n")
            f.write("|--|-----------------|------------------|\n")
            f.write(f"| actual benign | {cm[0][0]} | {cm[0][1]} |\n")
            f.write(f"| actual attack | {cm[1][0]} | {cm[1][1]} |\n\n")

            f.write(f"![confusion matrix]({name}_confusion_matrix.png)\n\n")
            f.write(f"![roc curve]({name}_roc_curve.png)\n\n")

            if 'top_features' in metrics:
                f.write("### top features\n\n")
                f.write("| feature | importance |\n")
                f.write("|---------|------------|\n")
                for feat in metrics['top_features']:
                    f.write(f"| {feat['feature']} | {feat['importance']:.4f} |\n")
                f.write(f"\n![feature importance]({name}_feature_importance.png)\n\n")

            f.write("### classification report\n\n")
            f.write(f"```\n{metrics['classification_report']}\n```\n\n")
            f.write("---\n\n")

    print(f"[*] training report written to {report_path}")


def main():
    if len(sys.argv) < 3:
        print("usage: train_model.py <benign.csv> <attack.csv> [output_dir]")
        sys.exit(1)

    benign_path = sys.argv[1]
    attack_path = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else '.'

    os.makedirs(output_dir, exist_ok=True)

    data = load_data(benign_path, attack_path)
    X, y, scaler, label_encoders, feature_names = preprocess(data)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"[*] train/test split: {len(X_train)} train, {len(X_test)} test")

    results, (best_name, best_model) = train_and_evaluate(
        X_train, X_test, y_train, y_test, feature_names, output_dir
    )

    # save the best model along with scaler and encoders
    model_path = os.path.join(output_dir, 'model.pkl')
    model_bundle = {
        'model': best_model,
        'scaler': scaler,
        'label_encoders': label_encoders,
        'feature_names': feature_names,
        'model_name': best_name
    }
    joblib.dump(model_bundle, model_path)
    print(f"\n[*] saved best model ({best_name}) to {model_path}")

    generate_report(results, output_dir)
    print("[*] training complete")


if __name__ == '__main__':
    main()
