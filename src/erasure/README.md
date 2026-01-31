┌─────────────────────────────────────────────────────────────┐
│                    ERASURE CODING                           │
└─────────────────────────────────────────────────────────────┘

Ficheiro Original: documento.pdf (100KB)

        CODIFICAÇÃO (k=4, n=10)
              │
              ▼
┌────┬────┬────┬────┬────┬────┬────┬────┬────┬────┐
│ S1 │ S2 │ S3 │ S4 │ P1 │ P2 │ P3 │ P4 │ P5 │ P6 │
│25KB│25KB│25KB│25KB│25KB│25KB│25KB│25KB│25KB│25KB│
└────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘
  │    │    │    │    │    │    │    │    │    │
  ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼
User User User User User User User User User User
  A    B    C    D    E    F    G    H    I    J

S = Shards (dados originais)
P = Paridade (redundância)

RECONSTRUÇÃO: Precisa de QUALQUER 4 dos 10 shards!

Cenário: Users B, C, E, F, G, H offline
          Restam: A(S1), D(S4), I(P5), J(P6)
          4 shards = FICHEIRO RECUPERADO ✓