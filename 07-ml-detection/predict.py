#!/usr/bin/env python3
"""real-time prediction using the trained ids model"""

import sys
import os
import json
import joblib
import numpy as np
import pandas as pd


def load_model(model_path):
    """load the saved model bundle"""
    if not os.path.exists(model_path):
        print(f"error: model file not found at {model_path}")
        sys.exit(1)

    bundle = joblib.load(model_path)
    print(f"[*] loaded {bundle['model_name']} model")
    return bundle


def predict_from_csv(bundle, csv_path):
    """run predictions on a csv file of network flows"""
    model = bundle['model']
    scaler = bundle['scaler']
    label_encoders = bundle['label_encoders']
    feature_names = bundle['feature_names']

    data = pd.read_csv(csv_path)

    # drop label column if present (we're predicting it)
    if 'label' in data.columns:
        actual_labels = data['label'].values
        data = data.drop('label', axis=1)
    else:
        actual_labels = None

    # encode categorical columns using the saved encoders
    for col, le in label_encoders.items():
        if col in data.columns:
            # handle unseen categories by mapping to the most common class
            data[col] = data[col].astype(str).apply(
                lambda x: le.transform([x])[0] if x in le.classes_ else 0
            )

    # handle missing values
    for col in data.columns:
        if data[col].dtype in ['float64', 'int64']:
            data[col] = data[col].fillna(data[col].median())

    # make sure columns match what the model expects
    for col in feature_names:
        if col not in data.columns:
            data[col] = 0
    data = data[feature_names]

    # scale features
    X = scaler.transform(data)

    # predict
    predictions = model.predict(X)
    probabilities = model.predict_proba(X)

    label_map = {0: 'benign', 1: 'attack'}
    results = []
    for i in range(len(predictions)):
        result = {
            'index': i,
            'prediction': label_map[predictions[i]],
            'confidence': float(max(probabilities[i])),
            'attack_probability': float(probabilities[i][1])
        }
        if actual_labels is not None:
            result['actual'] = actual_labels[i]
        results.append(result)

    return results


def predict_single(bundle, features_dict):
    """predict a single network flow from feature values"""
    model = bundle['model']
    scaler = bundle['scaler']
    label_encoders = bundle['label_encoders']
    feature_names = bundle['feature_names']

    # build a dataframe from the input
    data = pd.DataFrame([features_dict])

    # encode categoricals
    for col, le in label_encoders.items():
        if col in data.columns:
            val = str(data[col].iloc[0])
            data[col] = le.transform([val])[0] if val in le.classes_ else 0

    # ensure correct columns
    for col in feature_names:
        if col not in data.columns:
            data[col] = 0
    data = data[feature_names]

    X = scaler.transform(data)
    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0]

    label_map = {0: 'benign', 1: 'attack'}
    return {
        'prediction': label_map[prediction],
        'confidence': float(max(probability)),
        'attack_probability': float(probability[1])
    }


def main():
    if len(sys.argv) < 3:
        print("usage:")
        print("  predict.py <model.pkl> <input.csv>")
        print("  predict.py <model.pkl> --flow duration=0.5 protocol=tcp src_bytes=1024 ...")
        sys.exit(1)

    model_path = sys.argv[1]
    bundle = load_model(model_path)

    if sys.argv[2] == '--flow':
        # parse key=value pairs from command line
        features = {}
        for arg in sys.argv[3:]:
            if '=' not in arg:
                print(f"warning: skipping malformed argument '{arg}' (expected key=value)")
                continue
            key, val = arg.split('=', 1)
            try:
                features[key] = float(val)
            except ValueError:
                features[key] = val

        if not features:
            print("error: no features provided")
            sys.exit(1)

        print(f"[*] classifying single flow with {len(features)} features")
        result = predict_single(bundle, features)
        print(f"\n  prediction: {result['prediction']}")
        print(f"  confidence: {result['confidence']:.4f}")
        print(f"  attack probability: {result['attack_probability']:.4f}")

    else:
        csv_path = sys.argv[2]
        if not os.path.exists(csv_path):
            print(f"error: {csv_path} not found")
            sys.exit(1)

        print(f"[*] running predictions on {csv_path}")
        results = predict_from_csv(bundle, csv_path)

        # summary
        attacks = sum(1 for r in results if r['prediction'] == 'attack')
        benign = sum(1 for r in results if r['prediction'] == 'benign')
        print(f"\n[*] results: {len(results)} flows analysed")
        print(f"    benign: {benign}")
        print(f"    attack: {attacks}")

        # print detailed results
        print(f"\n{'idx':>4} {'prediction':>10} {'confidence':>10} {'attack_prob':>11}", end='')
        if results and 'actual' in results[0]:
            print(f" {'actual':>8} {'correct':>8}")
        else:
            print()

        for r in results:
            line = f"{r['index']:>4} {r['prediction']:>10} {r['confidence']:>10.4f} {r['attack_probability']:>11.4f}"
            if 'actual' in r:
                correct = 'yes' if r['prediction'] == r['actual'] else 'NO'
                line += f" {r['actual']:>8} {correct:>8}"
            print(line)

        # write results to json
        output_path = csv_path.replace('.csv', '_predictions.json')
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[*] results saved to {output_path}")


if __name__ == '__main__':
    main()
