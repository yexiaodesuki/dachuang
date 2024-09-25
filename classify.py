import time
from data_collect import *
from data_process import *
from predict import *
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib


def train_and_evaluate(X, y):
    print(f"Number of samples in X: {len(X)}")
    print(f"Number of samples in y: {len(y)}")

    if len(X) == 0 or len(y) == 0:
        raise ValueError("The input data is empty.")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.5, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred, zero_division=1))
    joblib.dump(clf, 'random_forest_model.pkl')


if __name__ == '__main__':
    batch_size = 30000
    '''
    print("Data collecting...")
    start_time = time.time()
    data_collect()
    collect_time = time.time() - start_time
    print("Finished collect")
    print("Collecting time:", collect_time)
    '''
    # print("Data processing...")
    # pcap_file = '1.pcap'
    # X, y = data_process(pcap_file, batch_size)
    # print("Finished process")
    # train_and_evaluate(X, y)
    test_file = 'test.pcap'
    predict(test_file, batch_size)









