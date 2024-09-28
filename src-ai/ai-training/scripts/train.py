import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
import matplotlib.pyplot as plt # data visualization
import seaborn as sns # statistical data visualization
from sklearn.model_selection import train_test_split
import category_encoders as ce
from sklearn.ensemble import RandomForestClassifier
import os
for dirname, _, filenames in os.walk('/kaggle/input'):
    for filename in filenames:
        print(os.path.join(dirname, filename))

import warnings

warnings.filterwarnings('ignore')

data = 'src-ai/ai-training/labels/malware.csv'

df = pd.read_csv(data, header=None)

col_names = ['type','hash','malice','generic','trojan','ransomware','worm','backdoor','spyware','rootkit','encrypter','downloader']


df.columns = col_names
col_names

df.head()

df.info()

for col in col_names:
    
    print(df[col].value_counts())   

df['worm'].value_counts()

df.isnull().sum()


X = df.drop(['ransomware'], axis=1)

y = df['ransomware']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print(X_train.dtypes)
print(X_train.head())

encoder = ce.OrdinalEncoder(cols=['type','hash','malice','generic','trojan','worm','backdoor','spyware','rootkit','encrypter','downloader'])


X_train = encoder.fit_transform(X_train)

X_test = encoder.transform(X_test)

print(X_train.head())

print(X_test.head())

rfc = RandomForestClassifier(n_estimators=100,criterion='entropy',random_state=0)



# fit the model

rfc.fit(X_train, y_train)



# Predict the Test set results

y_pred = rfc.predict(X_test)



# Check accuracy score 

from sklearn.metrics import accuracy_score

print('Model accuracy score with 400 decision-trees : {0:0.9f}'. format(accuracy_score(y_test, y_pred)))

clf = RandomForestClassifier(n_estimators=2000, random_state=32)

# fit the model to the training set

clf.fit(X_train, y_train)


feature_scores = pd.Series(clf.feature_importances_, index=X_train.columns).sort_values(ascending=False)

print(feature_scores)

X = df.drop(['spyware', 'type', 'ransomware', 'rootkit'], axis=1)

y = df['ransomware']

from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.1, random_state = 100)

encoder = ce.OrdinalEncoder(cols=['hash','malice','generic','trojan','worm','backdoor', 'encrypter','downloader'])


X_train = encoder.fit_transform(X_train)

X_test = encoder.transform(X_test)

clf = RandomForestClassifier(random_state=0)



# fit the model to the training set

clf.fit(X_train, y_train)


# Predict on the test set results

y_pred = clf.predict(X_test)



# Check accuracy score 

print('Model accuracy score with ransomware, spyware, rootkit, type variable removed : {0:0.4f}'. format(accuracy_score(y_test, y_pred)))

from sklearn.metrics import classification_report

print(classification_report(y_test, y_pred))

from sklearn.metrics import confusion_matrix

cm = confusion_matrix(y_test, y_pred)

print(cm)