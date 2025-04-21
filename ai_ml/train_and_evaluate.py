#!/usr/bin/env python3
"""
Train and evaluate the Enhanced Ransomware Detection Model.

This script trains the enhanced model on the provided dataset and 
evaluates its performance. It also provides visualization of the model's
performance metrics and feature importances.
"""

import os
import sys
import argparse
import logging
import json
import time
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, roc_curve, precision_recall_curve, auc
from sklearn.model_selection import learning_curve

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the enhanced model
from enhanced_detection_model import EnhancedRansomwareDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ModelTrainer")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Train and evaluate the ransomware detection model')
    
    parser.add_argument('--dataset', type=str, required=True, 
                        help='Path to the ransomware dataset CSV')
    
    parser.add_argument('--output-dir', type=str, default='./output',
                        help='Directory to save model and results')
    
    parser.add_argument('--tune-hyperparams', action='store_true',
                        help='Perform hyperparameter tuning (slower)')
    
    parser.add_argument('--visualize', action='store_true',
                        help='Generate visualization of model performance')
    
    parser.add_argument('--sample-files', type=str, nargs='+',
                        help='Sample files to test detection on')
    
    return parser.parse_args()

def visualize_results(model, features, labels, output_dir):
    """
    Visualize model performance metrics
    
    Args:
        model: Trained model
        features: Feature DataFrame
        labels: Label Series
        output_dir: Directory to save visualizations
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Get predictions
    predictions = model.classifier.predict(model.scaler.transform(features))
    probabilities = model.classifier.predict_proba(model.scaler.transform(features))[:, 0]  # Probability of being malicious
    
    # 1. Confusion Matrix
    cm = confusion_matrix(labels, predictions)
    plt.figure(figsize=(8, 6))
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('Confusion Matrix')
    plt.colorbar()
    tick_marks = np.arange(2)
    plt.xticks(tick_marks, ['Malicious', 'Benign'], rotation=45)
    plt.yticks(tick_marks, ['Malicious', 'Benign'])
    
    # Add text annotations
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, format(cm[i, j], 'd'),
                    horizontalalignment="center",
                    color="white" if cm[i, j] > thresh else "black")
    
    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
    plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'), dpi=300)
    plt.close()
    
    # 2. ROC Curve
    # Since our labels are 1=benign, 0=malicious, we need to invert for ROC
    fpr, tpr, _ = roc_curve(1-labels, probabilities)
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic')
    plt.legend(loc="lower right")
    plt.savefig(os.path.join(output_dir, 'roc_curve.png'), dpi=300)
    plt.close()
    
    # 3. Precision-Recall Curve
    precision, recall, _ = precision_recall_curve(1-labels, probabilities)
    pr_auc = auc(recall, precision)
    
    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, color='blue', lw=2, label=f'PR curve (area = {pr_auc:.2f})')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.legend(loc="lower left")
    plt.savefig(os.path.join(output_dir, 'pr_curve.png'), dpi=300)
    plt.close()
    
    # 4. Feature Importance
    if model.feature_importances and model.feature_names:
        # Sort feature importances
        importance_df = pd.DataFrame({
            'Feature': model.feature_names,
            'Importance': [model.feature_importances[f] for f in model.feature_names]
        })
        importance_df = importance_df.sort_values('Importance', ascending=False)
        
        # Plot top 10 features
        plt.figure(figsize=(10, 6))
        plt.barh(importance_df['Feature'][:10], importance_df['Importance'][:10])
        plt.xlabel('Importance')
        plt.title('Top 10 Feature Importances')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'feature_importance.png'), dpi=300)
        plt.close()
    
    # 5. Learning Curve
    # This shows how the model performs with increasing amounts of training data
    train_sizes, train_scores, test_scores = learning_curve(
        model.classifier, model.scaler.transform(features), labels, 
        cv=5, n_jobs=-1, train_sizes=np.linspace(0.1, 1.0, 10)
    )
    
    train_mean = np.mean(train_scores, axis=1)
    train_std = np.std(train_scores, axis=1)
    test_mean = np.mean(test_scores, axis=1)
    test_std = np.std(test_scores, axis=1)
    
    plt.figure(figsize=(10, 6))
    plt.plot(train_sizes, train_mean, color='blue', marker='o', markersize=5, label='Training score')
    plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.15, color='blue')
    plt.plot(train_sizes, test_mean, color='green', marker='s', markersize=5, label='Validation score')
    plt.fill_between(train_sizes, test_mean - test_std, test_mean + test_std, alpha=0.15, color='green')
    plt.xlabel('Training Size')
    plt.ylabel('Score')
    plt.title('Learning Curve')
    plt.legend(loc='lower right')
    plt.grid()
    plt.savefig(os.path.join(output_dir, 'learning_curve.png'), dpi=300)
    plt.close()
    
    logger.info(f"Visualizations saved to {output_dir}")

def test_sample_files(model, file_paths):
    """
    Test the model on sample files
    
    Args:
        model: Trained model
        file_paths: List of file paths to test
    """
    logger.info("Testing sample files:")
    
    results = []
    for file_path in file_paths:
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            continue
            
        logger.info(f"Analyzing: {file_path}")
        
        # Analyze file
        analysis = model.analyze_file(file_path)
        
        # Print results
        logger.info(f"  File: {os.path.basename(file_path)}")
        logger.info(f"  Risk Score: {analysis['risk_score']:.2f}")
        logger.info(f"  Risk Level: {analysis['risk_level']}")
        logger.info(f"  Threats: {', '.join(analysis['threats']) if analysis['threats'] else 'None'}")
        logger.info(f"  Key Factors: {list(analysis['detection_factors'].keys())[:3]}")
        logger.info("-" * 50)
        
        results.append({
            'file': os.path.basename(file_path),
            'risk_score': analysis['risk_score'],
            'risk_level': analysis['risk_level'],
            'threats': analysis['threats']
        })
    
    return results

def main():
    """Main function to train and evaluate the model"""
    # Parse arguments
    args = parse_arguments()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Create and initialize the model
    logger.info("Initializing enhanced ransomware detector")
    model = EnhancedRansomwareDetector(model_dir=args.output_dir)
    
    # Check if dataset exists
    if not os.path.exists(args.dataset):
        logger.error(f"Dataset not found: {args.dataset}")
        return 1
    
    # Load the dataset
    logger.info(f"Loading dataset: {args.dataset}")
    features, labels = model.load_dataset(args.dataset)
    
    if features is None or labels is None:
        logger.error("Failed to load dataset")
        return 1
    
    # Train the model
    logger.info("Training model...")
    start_time = time.time()
    success = model.train_model(features, labels, tune_hyperparams=args.tune_hyperparams)
    
    if not success:
        logger.error("Model training failed")
        return 1
    
    # Log training time
    training_time = time.time() - start_time
    logger.info(f"Model trained successfully in {training_time:.2f} seconds")
    
    # Get model info
    model_info = model.get_model_info()
    
    # Save model info to file
    with open(os.path.join(args.output_dir, 'model_info.json'), 'w') as f:
        json.dump(model_info, f, indent=2)
    
    # Generate visualizations if requested
    if args.visualize:
        logger.info("Generating visualizations...")
        visualize_results(model, features, labels, args.output_dir)
    
    # Test sample files if provided
    if args.sample_files:
        sample_results = test_sample_files(model, args.sample_files)
        
        # Save sample results to file
        with open(os.path.join(args.output_dir, 'sample_results.json'), 'w') as f:
            json.dump(sample_results, f, indent=2)
    
    logger.info("Done!")
    return 0

if __name__ == "__main__":
    sys.exit(main())