CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, username TEXT NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'client',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS plans (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, storage_gb INTEGER NOT NULL,
  price_label TEXT NOT NULL DEFAULT 'Grátis', description TEXT DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cities (
  id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, name TEXT NOT NULL,
  plan_id TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner_id) REFERENCES users(id), FOREIGN KEY(plan_id) REFERENCES plans(id)
);
CREATE TABLE IF NOT EXISTS city_files (
  id TEXT PRIMARY KEY, city_id TEXT NOT NULL, object_key TEXT NOT NULL UNIQUE,
  file_name TEXT NOT NULL, size_bytes INTEGER NOT NULL, uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(city_id) REFERENCES cities(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY, actor_id TEXT, action TEXT NOT NULL, detail TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO plans(id,name,storage_gb,price_label,description,enabled) VALUES
('free','FREE',2,'Grátis','Plano gratuito de demonstração',1),
('starter','STARTER',10,'Grátis','Plano de entrada',1),
('pro','PRO',50,'Grátis','Plano avançado',1),
('ultimate','ULTIMATE',100,'Grátis','Plano premium',1),
('full-ultimate','FULL ULTIMATE',200,'Grátis','Plano máximo FUST HOST',1);
