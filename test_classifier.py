"""
test_classifier.py — Test the AI classifier with sample events.
Run: python test_classifier.py
"""
from ml.predict import classify

test_events = [
    {
        "service": "SSH", "event_type": "AUTH_ATTEMPT",
        "details": {"username": "root", "password": "123456"}
    },
    {
        "service": "HTTP", "event_type": "SQLI_ATTEMPT",
        "details": {"path": "/search?q=' OR 1=1--", "method": "GET"}
    },
    {
        "service": "SSH", "event_type": "CONNECTION",
        "details": {"status": "connected"}
    },
    {
        "service": "HTTP", "event_type": "ADMIN_ACCESS",
        "details": {"path": "/wp-admin", "username": "admin", "password": "admin"}
    },
    {
        "service": "SSH", "event_type": "COMMAND",
        "details": {"command": "cat /etc/passwd"}
    },
    {
        "service": "HTTP", "event_type": "PATH_TRAVERSAL",
        "details": {"path": "/../../../etc/passwd"}
    },
]

print("\nAI Classifier Test\n" + "="*50)
for event in test_events:
    result = classify(event)
    if result:
        print(f"Service  : {event['service']}")
        print(f"Event    : {event['event_type']}")
        print(f"AI Label : {result['name']}")
        print(f"Confidence: {result['confidence']*100:.1f}%")
        print(f"Severity : {result['severity'].upper()}")
        print("-"*50)
    else:
        print("Model not loaded — run: python -m ml.train")