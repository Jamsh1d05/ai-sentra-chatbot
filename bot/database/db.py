import aiosqlite

DB_PATH = "data/sentra_bot.db"

class Database:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    async def init_db(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER NOT NULL UNIQUE,
                    first_name TEXT,
                    username TEXT,
                    subscribed BOOLEAN DEFAULT TRUE,
                    language TEXT DEFAULT 'en',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP            
                )
            """)
        

            await db.execute("""
                CREATE TABLE IF NOT EXISTS sources(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT NOT NULL UNIQUE,
                    source_url TEXT NOT NULL
                )
            """)
            

            await db.execute("""
                CREATE TABLE IF NOT EXISTS cve (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    bulletin_id TEXT NOT NULL UNIQUE,
                    source_id INTEGER NOT NULL, 
                    description TEXT,
                    base_score REAL,
                    base_severity TEXT,
                    published_date TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    notified BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
                )
            """)


            await db.execute("""
                CREATE TABLE IF NOT EXISTS cpe (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    cpe_uri TEXT NOT NULL,
                    UNIQUE(cve_id, cpe_uri), 
                    FOREIGN KEY (cve_id) REFERENCES cve(bulletin_id) ON DELETE CASCADE
                )
            """)


            await db.execute("""
                CREATE TABLE IF NOT EXISTS user_subscriptions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    source_id INTEGER NOT NULL,
                    subscribed BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
                );
            """)
            

            await db.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    file_name TEXT,
                    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            await self.insert_default_sources(db)

            await db.commit()

    async def insert_default_sources(self, db):
        cursor = await db.execute("SELECT COUNT(*) FROM sources")
        count = await cursor.fetchone()
        
        if count[0] == 0:
            defaul_sources = [
                ("Microsoft", ""),
                ("Apple", ""),
                ("Google", ""),
                ("Cisco", ""),
                ("Linux", ""),
                ("Oracle", ""),
                ("Adobe", ""),
                ("VMware", ""),
                ("Intel", ""),
                ("Mozilla", ""),
                ("Samsung", ""),
                ("Huawei", ""),
            ]
            await db.executemany(
                "INSERT INTO sources (source_name, source_url) VALUES (?, ?)",
                defaul_sources
            )
    async def is_registered(self, chat_id):
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT chat_id FROM users WHERE chat_id = ?", (chat_id,))
            row = await cursor.fetchone()
            return row is not None


    async def add_user(self, chat_id, first_name, username, language):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR IGNORE INTO users (chat_id, first_name, username, language)
                VALUES (?, ?, ?, ?)
            """, (chat_id, first_name, username, language))

            #Subscribe the user to default source
            await db.execute("""
                INSERT OR IGNORE INTO user_subscriptions (user_id, source_id)
                VALUES (?, (SELECT id FROM sources WHERE source_name = 'NVD'))
            """, (chat_id,))
            await db.commit()

    async def get_user_language(self, chat_id):
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT language FROM users WHERE chat_id = ?", (chat_id,))
            row = await cursor.fetchone()
            return row[0] if row else "en"

    async def set_user_language(self, chat_id, language):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("UPDATE users SET language = ? WHERE chat_id = ?", (language, chat_id))
            await db.commit()

    async def add_cve(self, bulletin_id, source_id, description, base_score, base_severity, published_date):
        async with aiosqlite.connect(self.db_path) as db:
            try:
                sql_query = """  
                INSERT OR IGNORE INTO cve (bulletin_id, source_id, description, base_score, base_severity, published_date)
                VALUES (?, ?, ?, ?, ?, ?)
                """
                await db.execute(sql_query, (bulletin_id, source_id, description, base_score, base_severity, published_date))
            except Exception as e:
                print(f"Error in add_cve function: {e}")
                raise
            await db.commit()

    async def add_cpe(self, cve_id, cpe_uri):
        async with aiosqlite.connect(self.db_path) as db:
            try:
                sql_query = """
                INSERT OR IGNORE INTO cpe (cve_id, cpe_uri)
                VALUES (?, ?)
                """
                await db.execute(sql_query, (cve_id, cpe_uri))
            except Exception as e:
                print(f"Error in add_cpe function: {e}")
                raise
            await db.commit()

    async def get_cpe_by_cve_id(self, cve_id):
        async with aiosqlite.connect(self.db_path) as db:
            query = "SELECT cpe_uri FROM cpe WHERE cve_id = ?"
            cursor = await db.execute(query, (cve_id,))
            rows = await cursor.fetchall()
            return [row[0] for row in rows]
        

    ''' ========================= Subscription ========================= '''

    async def get_all_subscribed_users(self):
        async with aiosqlite.connect(self.db_path) as db:
            query = """
            SELECT DISTINCT users.chat_id
            FROM users
            JOIN user_subscriptions ON users.chat_id = user_subscriptions.user_id
            WHERE user_subscriptions.subscribed = 1
            """
            cursor = await db.execute(query)
            rows = await cursor.fetchall()
            return [row[0] for row in rows]
        

    async def get_all_sources(self):
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT source_name FROM sources")    
            rows = await cursor.fetchall()
            return [row[0] for row in rows] 
        
    async def get_source_id_by_name(self, source_name: str) -> int | None:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT id FROM sources WHERE source_name = ?", (source_name,))
            row = await cursor.fetchone()
            return row[0] if row else None

    async def get_user_subscribed_sources(self, chat_id: int) -> list[str]:
        async with aiosqlite.connect(self.db_path) as db:
            query = """
            SELECT s.source_name
            FROM user_subscriptions us
            JOIN users u ON us.user_id = u.chat_id
            JOIN sources s ON us.source_id = s.id
            WHERE u.chat_id = ? AND us.subscribed = 1
            """
            cursor = await db.execute(query, (chat_id,))
            rows = await cursor.fetchall()
            return [row[0] for row in rows]

    async def is_user_subscribed_to_source(self, chat_id: int, source_id: int) -> bool:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("""
                SELECT subscribed FROM user_subscriptions
                WHERE user_id = ? AND source_id = ?
            """, (chat_id, source_id))
            row = await cursor.fetchone()
            return row is not None and row[0] == 1

    async def subscribe_user_to_source(self, chat_id: int, source_id: int):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO user_subscriptions (user_id, source_id, subscribed)
                VALUES (?, ?, 1)
                ON CONFLICT(user_id, source_id) DO UPDATE SET subscribed = 1
            """, (chat_id, source_id))
            await db.commit()

    async def unsubscribe_user_from_source(self, chat_id: int, source_id: int):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                UPDATE user_subscriptions SET subscribed = 0
                WHERE user_id = ? AND source_id = ?
            """, (chat_id, source_id))
            await db.commit()

    async def get_user_sources(self, chat_id: int) -> list[str]:
        async with aiosqlite.connect(self.db_path) as db:
            query = """
            SELECT s.source_name
            FROM user_subscriptions us
            JOIN sources s ON us.source_id = s.id
            WHERE us.user_id = ? AND us.subscribed = 1
            """
            cursor = await db.execute(query, (chat_id,))
            rows = await cursor.fetchall()
            return [row[0] for row in rows]

    '''' ========================= End ========================= '''


    async def check_bulletin_status(self, cve_id):
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT notified FROM cve WHERE bulletin_id = ?", (cve_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return bool(row[0]) 
                return False

    async def update_bulletin_notified(self, cve_id):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE cve SET notified = TRUE WHERE bulletin_id = ?",
                (cve_id,)
            )
            await db.commit()

    async def search_cves(self, keyword):
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            query = """
            SELECT * FROM cve
            WHERE description LIKE ? OR bulletin_id LIKE ? OR base_severity LIKE ? OR published_date LIKE ?
            LIMIT 10
            """
            cursor = await db.execute(query, (f'%{keyword}%', f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'))
            result = await cursor.fetchall()
            return [dict(row) for row in result]

    async def save_log_metadata(self,user_id, file_name):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("INSERT INTO logs (user_id, file_name) VALUES (?, ?)", (user_id, file_name))
            await db.commit()


            