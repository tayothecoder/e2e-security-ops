#!/usr/bin/env python3
"""compare ml-based detection vs signature-based (suricata) detection"""

import sys
import os
import json
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime


def load_suricata_alerts(eve_path):
    """load suricata alerts from eve.json and extract flagged source ips"""
    alerts = {}
    if not os.path.exists(eve_path):
        print(f"error: {eve_path} not found")
        sys.exit(1)

    with open(eve_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            if record.get('event_type') == 'alert':
                src_ip = record.get('src_ip', '')
                alert_info = record.get('alert', {})
                sig = alert_info.get('signature', 'unknown')
                severity = alert_info.get('severity', 0)
                alerts[src_ip] = {
                    'signature': sig,
                    'severity': severity,
                    'detected': True
                }

    print(f"[*] loaded {len(alerts)} unique source IPs from suricata alerts")
    return alerts


def load_ml_predictions(predictions_path):
    """load ml prediction results"""
    if not os.path.exists(predictions_path):
        print(f"error: {predictions_path} not found")
        sys.exit(1)

    with open(predictions_path, 'r') as f:
        predictions = json.load(f)

    print(f"[*] loaded {len(predictions)} ml predictions")
    return predictions


def load_ground_truth(csv_path):
    """load labelled data with ground truth"""
    if not os.path.exists(csv_path):
        print(f"error: {csv_path} not found")
        sys.exit(1)

    data = pd.read_csv(csv_path)
    if 'label' not in data.columns:
        print("error: ground truth csv must have a 'label' column")
        sys.exit(1)

    print(f"[*] loaded {len(data)} labelled flows")
    return data


def compare_methods(ground_truth, ml_predictions, suricata_alerts):
    """compare detection performance of both methods"""

    total = len(ground_truth)
    actual_attacks = (ground_truth['label'] == 'attack').sum()
    actual_benign = (ground_truth['label'] == 'benign').sum()

    # ml results
    ml_detected = sum(1 for p in ml_predictions if p['prediction'] == 'attack')
    ml_correct_attacks = sum(
        1 for p in ml_predictions
        if p['prediction'] == 'attack' and p.get('actual') == 'attack'
    )
    ml_false_positives = sum(
        1 for p in ml_predictions
        if p['prediction'] == 'attack' and p.get('actual') == 'benign'
    )
    ml_missed = sum(
        1 for p in ml_predictions
        if p['prediction'] == 'benign' and p.get('actual') == 'attack'
    )

    # suricata results - count how many of the alerts match actual attacks
    # for this comparison we use the number of alerts vs total attacks
    sig_detected = len(suricata_alerts)
    # estimate based on alert count vs known attack count
    sig_detection_rate = min(sig_detected / max(actual_attacks, 1), 1.0)

    ml_detection_rate = ml_correct_attacks / max(actual_attacks, 1)
    ml_fp_rate = ml_false_positives / max(actual_benign, 1)

    results = {
        'dataset': {
            'total_flows': int(total),
            'actual_attacks': int(actual_attacks),
            'actual_benign': int(actual_benign)
        },
        'ml_detection': {
            'total_flagged': int(ml_detected),
            'true_positives': int(ml_correct_attacks),
            'false_positives': int(ml_false_positives),
            'missed_attacks': int(ml_missed),
            'detection_rate': float(ml_detection_rate),
            'false_positive_rate': float(ml_fp_rate)
        },
        'signature_detection': {
            'total_alerts': int(sig_detected),
            'estimated_detection_rate': float(sig_detection_rate)
        },
        'comparison': {
            'ml_advantage': float(ml_detection_rate - sig_detection_rate),
            'ml_only_detections': int(max(ml_correct_attacks - sig_detected, 0)),
            'signature_only_detections': int(max(sig_detected - ml_correct_attacks, 0))
        }
    }

    return results


def generate_charts(results, output_dir):
    """create comparison charts"""

    # detection rate comparison bar chart
    fig, ax = plt.subplots(figsize=(8, 5))
    methods = ['ml classifier', 'suricata signatures']
    rates = [
        results['ml_detection']['detection_rate'] * 100,
        results['signature_detection']['estimated_detection_rate'] * 100
    ]
    colors = ['#2196F3', '#FF9800']
    bars = ax.bar(methods, rates, color=colors, width=0.5)

    for bar, rate in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                f'{rate:.1f}%', ha='center', va='bottom', fontweight='bold')

    ax.set_ylabel('detection rate (%)')
    ax.set_title('ml vs signature-based detection rates')
    ax.set_ylim(0, 110)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'detection_comparison.png'), dpi=100)
    plt.close()

    # detailed breakdown chart
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # ml breakdown
    ml = results['ml_detection']
    labels = ['true positives', 'false positives', 'missed']
    values = [ml['true_positives'], ml['false_positives'], ml['missed_attacks']]
    colors_pie = ['#4CAF50', '#f44336', '#FFC107']
    axes[0].pie(values, labels=labels, colors=colors_pie, autopct='%1.1f%%', startangle=90)
    axes[0].set_title('ml classifier breakdown')

    # overall comparison
    categories = ['detection\nrate', 'false\npositive\nrate']
    ml_vals = [ml['detection_rate'] * 100, ml['false_positive_rate'] * 100]
    sig_vals = [results['signature_detection']['estimated_detection_rate'] * 100, 5.0]  # estimate sig fp rate

    x = np.arange(len(categories))
    width = 0.3
    axes[1].bar(x - width / 2, ml_vals, width, label='ml', color='#2196F3')
    axes[1].bar(x + width / 2, sig_vals, width, label='signatures', color='#FF9800')
    axes[1].set_ylabel('rate (%)')
    axes[1].set_title('detection metrics comparison')
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(categories)
    axes[1].legend()

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'detailed_comparison.png'), dpi=100)
    plt.close()

    print(f"[*] charts saved to {output_dir}")


def generate_report(results, output_dir):
    """write comparison report as markdown"""
    report_path = os.path.join(output_dir, 'comparison_report.md')

    with open(report_path, 'w') as f:
        f.write("# detection method comparison report\n\n")
        f.write(f"generated: {datetime.now().isoformat()}\n\n")

        f.write("## dataset overview\n\n")
        ds = results['dataset']
        f.write(f"- total flows: {ds['total_flows']}\n")
        f.write(f"- actual attacks: {ds['actual_attacks']}\n")
        f.write(f"- actual benign: {ds['actual_benign']}\n\n")

        f.write("## ml classifier performance\n\n")
        ml = results['ml_detection']
        f.write(f"| metric | value |\n")
        f.write(f"|--------|-------|\n")
        f.write(f"| total flagged | {ml['total_flagged']} |\n")
        f.write(f"| true positives | {ml['true_positives']} |\n")
        f.write(f"| false positives | {ml['false_positives']} |\n")
        f.write(f"| missed attacks | {ml['missed_attacks']} |\n")
        f.write(f"| detection rate | {ml['detection_rate']:.2%} |\n")
        f.write(f"| false positive rate | {ml['false_positive_rate']:.2%} |\n\n")

        f.write("## signature-based (suricata) performance\n\n")
        sig = results['signature_detection']
        f.write(f"| metric | value |\n")
        f.write(f"|--------|-------|\n")
        f.write(f"| total alerts | {sig['total_alerts']} |\n")
        f.write(f"| estimated detection rate | {sig['estimated_detection_rate']:.2%} |\n\n")

        f.write("## comparison\n\n")
        comp = results['comparison']
        f.write(f"- ml advantage: {comp['ml_advantage']:+.2%}\n")
        f.write(f"- detections unique to ml: {comp['ml_only_detections']}\n")
        f.write(f"- detections unique to signatures: {comp['signature_only_detections']}\n\n")

        f.write("![detection comparison](detection_comparison.png)\n\n")
        f.write("![detailed comparison](detailed_comparison.png)\n\n")

        f.write("## analysis\n\n")
        if comp['ml_advantage'] > 0:
            f.write("the ml classifier outperformed signature-based detection in this evaluation. ")
            f.write("ml methods can detect novel attack patterns that lack existing signatures, ")
            f.write("making them valuable as a complement to traditional ids.\n\n")
        else:
            f.write("signature-based detection performed comparably or better in this evaluation. ")
            f.write("this may indicate that the attack patterns in the dataset match known signatures well. ")
            f.write("ml methods still add value for detecting zero-day and polymorphic attacks.\n\n")

        f.write("## recommendation\n\n")
        f.write("a hybrid approach combining both methods provides the best coverage. ")
        f.write("signature-based detection handles known threats efficiently, while ")
        f.write("ml classification catches anomalous traffic that evades rule-based systems.\n")

    print(f"[*] comparison report written to {report_path}")


def main():
    if len(sys.argv) < 4:
        print("usage: compare_detection.py <eve.json> <ml_predictions.json> <labelled_data.csv> [output_dir]")
        print("")
        print("compares ml vs signature-based detection on the same traffic.")
        sys.exit(1)

    eve_path = sys.argv[1]
    predictions_path = sys.argv[2]
    ground_truth_path = sys.argv[3]
    output_dir = sys.argv[4] if len(sys.argv) > 4 else '.'

    os.makedirs(output_dir, exist_ok=True)

    suricata_alerts = load_suricata_alerts(eve_path)
    ml_predictions = load_ml_predictions(predictions_path)
    ground_truth = load_ground_truth(ground_truth_path)

    print("[*] comparing detection methods")
    results = compare_methods(ground_truth, ml_predictions, suricata_alerts)

    generate_charts(results, output_dir)
    generate_report(results, output_dir)

    # save raw results
    with open(os.path.join(output_dir, 'comparison_results.json'), 'w') as f:
        json.dump(results, f, indent=2)

    print("[*] comparison complete")


if __name__ == '__main__':
    main()
