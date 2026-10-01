def generate_learning_recommendations(category_scores):
    recommendations = []
    for category, score in category_scores.items():
        if score < 60:
            recommendations.append({
                "category": category,
                "score": score,
                "recommendation": f"Review the {category} awareness module and retake the related quiz questions."
            })
    return recommendations
