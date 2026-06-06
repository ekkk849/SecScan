# db_builder.py
import sqlite3, random, string
from collections import defaultdict
from graphlib import TopologicalSorter

DB_FILE = "simulation.db"

FIRST_NAMES = ["Alice","Bob","Carol","David","Emma","Frank","Grace","Henry","Isla","Jack","Karen","Liam","Mia","Noah","Olivia","Peter"]
LAST_NAMES  = ["Smith","Jones","Taylor","Brown","Wilson","Evans","Roberts","Walker","White","Hall","Wood","Martin"]
CITIES      = ["London","Manchester","Birmingham","Leeds","Bristol","Edinburgh","Cardiff","Glasgow","Liverpool"]
STATUSES    = ["active","inactive","pending","suspended","verified"]
CATEGORIES  = ["Electronics","Clothing","Food","Books","Furniture","Toys","Sports"]
EMAIL_DOMS  = ["gmail.com","outlook.com","yahoo.com","company.co.uk","work.org"]


class DBBuilder:
    def __init__(self, parsed_data: dict):
        self.columns      = parsed_data["columns"]       # table -> [col, ...]
        self.joins        = parsed_data["joins"]         # [[lt,lc,rt,rc], ...]
        self.column_types = parsed_data["column_types"]  # table -> {col: type}
        self.schema_sql: list = []

    # ── FK inference ──────────────────────────────────────────────────────
    def infer_foreign_keys(self) -> dict:
        """
        Returns {child_table: [(child_col, parent_table, parent_col), ...]}
        
        Rule: whichever side's column name contains the OTHER table's name
        (singularised) is the child. E.g. Orders.CustomerId -> Customers.
        """
        fk_map = defaultdict(list)
        for lt, lc, rt, rc in self.joins:
            if lt == rt:
                continue
            lt_sing = lt.lower().rstrip('s')
            rt_sing = rt.lower().rstrip('s')
            lc_low  = lc.lower()
            rc_low  = rc.lower()

            if rt_sing in lc_low and lc_low.endswith('id'):
                fk_map[lt].append((lc, rt, rc))
            elif lt_sing in rc_low and rc_low.endswith('id'):
                fk_map[rt].append((rc, lt, lc))
            elif lc_low.endswith('id') and lc_low != f"{lt_sing}id":
                fk_map[lt].append((lc, rt, rc))
            elif rc_low.endswith('id') and rc_low != f"{rt_sing}id":
                fk_map[rt].append((rc, lt, lc))
            # skip ambiguous joins — don't add bad FK constraints

        return dict(fk_map)

    # ── Topological sort ──────────────────────────────────────────────────
    def _topo_order(self, fk_map: dict) -> list:
        graph = {t: set() for t in self.columns}
        for child, fks in fk_map.items():
            for _, parent, _ in fks:
                if parent in graph:
                    graph.setdefault(child, set()).add(parent)
        try:
            return list(TopologicalSorter(graph).static_order())
        except Exception:
            return list(self.columns.keys())

    # ── Schema build ──────────────────────────────────────────────────────
    def build(self) -> list:
        fk_map = self.infer_foreign_keys()
        self.schema_sql = []

        for table, cols in self.columns.items():
            if not cols:
                cols = [f"{table}Id"]
                self.column_types.setdefault(table, {})[f"{table}Id"] = "INTEGER"

            # Identify natural PK column (e.g. CustomerId in Customers,
            # ProductId in Products — try both plural and singular form)
            t_lower = table.lower()
            t_sing  = t_lower.rstrip('s')   # Products -> product, Orders -> order
            pk_col = next(
                (c for c in cols
                 if c.lower() in (f"{t_lower}id", f"{t_sing}id")),
                None
            )

            col_defs = []
            if pk_col:
                col_defs.append(f'"{pk_col}" INTEGER PRIMARY KEY AUTOINCREMENT')
            else:
                col_defs.append('"_id" INTEGER PRIMARY KEY AUTOINCREMENT')

            for col in cols:
                if col == pk_col:
                    continue
                ctype = self.column_types.get(table, {}).get(col, "TEXT")
                col_defs.append(f'"{col}" {ctype}')

            # Only add FK constraints where the parent PK is known and matches
            for child_col, parent_table, parent_col in fk_map.get(table, []):
                parent_pk = next(
                    (c for c in self.columns.get(parent_table, [])
                     if c.lower() == f"{parent_table.lower()}id"),
                    None
                )
                if parent_pk and parent_pk == parent_col:
                    col_defs.append(
                        f'FOREIGN KEY ("{child_col}") REFERENCES "{parent_table}"("{parent_col}")'
                    )
                # else: skip — avoids FK mismatch errors

            stmt = (
                f'CREATE TABLE IF NOT EXISTS "{table}" (\n  '
                + ',\n  '.join(col_defs)
                + '\n);'
            )
            self.schema_sql.append(stmt)

        return self.schema_sql

    # ── Populate ──────────────────────────────────────────────────────────
    def execute_and_populate(self, rows_per_table: int = 25):
        fk_map   = self.infer_foreign_keys()
        order    = self._topo_order(fk_map)
        schema   = self.build()

        conn = sqlite3.connect(DB_FILE)
        cur  = conn.cursor()
        cur.execute("PRAGMA foreign_keys = OFF;")  # off during bulk load
        cur.execute("PRAGMA journal_mode = WAL;")

        for stmt in schema:
            cur.execute(stmt)
        conn.commit()

        inserted_ids: dict[str, list] = defaultdict(list)
        fk_col_map: dict[str, dict]   = {}   # table -> {col: parent_table}
        for child, fks in fk_map.items():
            fk_col_map[child] = {fc: pt for fc, pt, _ in fks}

        for table in order:
            cols = self.columns.get(table)
            if not cols:
                continue

            t_lower    = table.lower()
            t_sing     = t_lower.rstrip('s')
            pk_col     = next(
                (c for c in cols
                 if c.lower() in (f"{t_lower}id", f"{t_sing}id")),
                None
            )
            insert_cols = [c for c in cols if c != pk_col]
            fk_lookup   = fk_col_map.get(table, {})

            for _ in range(rows_per_table):
                values = []
                for col in insert_cols:
                    if col in fk_lookup:
                        parent = fk_lookup[col]
                        values.append(
                            random.choice(inserted_ids[parent])
                            if inserted_ids[parent] else 1
                        )
                    else:
                        ctype = self.column_types.get(table, {}).get(col, "TEXT")
                        values.append(self._gen(col, ctype))

                if not insert_cols:
                    cur.execute(f'INSERT INTO "{table}" DEFAULT VALUES')
                else:
                    ph  = ",".join(["?"] * len(values))
                    cls = ",".join([f'"{c}"' for c in insert_cols])
                    cur.execute(f'INSERT INTO "{table}" ({cls}) VALUES ({ph})', values)

                inserted_ids[table].append(cur.lastrowid)

        conn.commit()
        conn.close()

    def _gen(self, col: str, ctype: str):
        low = col.lower()
        if ctype == "INTEGER":
            if "age"      in low: return random.randint(18, 80)
            if "qty" in low or "quantity" in low: return random.randint(1, 100)
            if "stock"    in low: return random.randint(0, 500)
            if "year"     in low: return random.randint(2010, 2024)
            if "floor"    in low: return random.randint(1, 10)
            return random.randint(1, 9999)
        if ctype == "REAL":
            if "price" in low or "cost" in low: return round(random.uniform(0.99, 4999.99), 2)
            if "salary"  in low: return round(random.uniform(25000, 150000), 2)
            if "rate"    in low: return round(random.uniform(0.01, 1.0), 4)
            if "balance" in low: return round(random.uniform(-500, 50000), 2)
            if "dosage"  in low: return round(random.uniform(0.5, 500.0), 2)
            return round(random.uniform(1.0, 10000.0), 2)
        if ctype == "DATE":
            return f"{random.randint(2018,2024)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}"
        # TEXT
        if "email"      in low: return f"{random.choice(FIRST_NAMES).lower()}.{random.choice(LAST_NAMES).lower()}@{random.choice(EMAIL_DOMS)}"
        if "firstname"  in low or ("first" in low and "name" in low): return random.choice(FIRST_NAMES)
        if "lastname"   in low or ("last"  in low and "name" in low): return random.choice(LAST_NAMES)
        if "name"       in low: return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
        if "city"       in low or "town" in low: return random.choice(CITIES)
        if "country"    in low: return random.choice(["UK","USA","Germany","France","Canada"])
        if "status"     in low: return random.choice(STATUSES)
        if "category"   in low or "type" in low: return random.choice(CATEGORIES)
        if "phone"      in low or "mobile" in low: return f"+44 7{random.randint(100,999)} {random.randint(100000,999999)}"
        if "postcode"   in low or "zip" in low: return f"{''.join(random.choices(string.ascii_uppercase,k=2))}{random.randint(1,20)}"
        if "description" in low or "notes" in low: return " ".join(random.choices(["quality","premium","standard","basic"],k=3))
        if "code"       in low or "ref"  in low: return f"{''.join(random.choices(string.ascii_uppercase,k=3))}-{random.randint(1000,9999)}"
        if "nhsnumber"  in low or "nhs"  in low: return f"{random.randint(100,999)} {random.randint(100,999)} {random.randint(1000,9999)}"
        if "bloodtype"  in low: return random.choice(["A+","A-","B+","B-","AB+","AB-","O+","O-"])
        if "allerg"     in low: return random.choice(["None","Penicillin","Aspirin","Peanuts","Latex"])
        if "ingredient" in low: return random.choice(["Paracetamol","Ibuprofen","Amoxicillin","Metformin"])
        if "strength"   in low: return random.choice(["5mg","10mg","25mg","50mg","100mg","500mg"])
        if "specialisa" in low or "special" in low: return random.choice(["Cardiology","Neurology","Oncology","Paediatrics","General"])
        if "ward"       in low: return random.choice(["Ward A","Ward B","ICU","Maternity","Oncology","Surgical"])
        if "shifttype"  in low: return random.choice(["morning","afternoon","night","on-call"])
        if "batch"      in low: return f"BATCH-{random.randint(10000,99999)}"
        if "frequency"  in low: return random.choice(["once daily","twice daily","three times daily","as needed"])
        if "activeingr" in low: return random.choice(["Paracetamol","Ibuprofen","Codeine","Omeprazole"])
        return ''.join(random.choices(string.ascii_letters, k=random.randint(6,12)))

    @property
    def column_counts(self) -> dict:
        return {t: len(c) for t, c in self.columns.items()}
