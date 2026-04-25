from app.database import SessionLocal
from app.models.data import PatientRecord
import pandas as pd

db = SessionLocal()
records = db.query(PatientRecord).all()
db.close()

df = pd.DataFrame([{'age':r.age,'zipcode':r.zipcode,'gender':r.gender} for r in records])

def ga(a): base=(a//10)*10; return f'{base}-{base+9}'
def gz(z): return str(z)[:3]+'**'

df['age'] = df['age'].apply(ga)
df['zipcode'] = df['zipcode'].apply(gz)
gs = df.groupby(['age','zipcode','gender']).size().reset_index(name='count')
print(gs[gs['count'] < 2].to_string())
print('Total groups with count < 2:', len(gs[gs['count'] < 2]))