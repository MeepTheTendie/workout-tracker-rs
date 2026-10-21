-- Workout Tracker schema for D1 (SQLite)

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    created_at INTEGER,
    updated_at INTEGER
);

CREATE TABLE exercises (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    created_at INTEGER,
    updated_at INTEGER
);

CREATE TABLE workouts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    notes TEXT,
    created_at INTEGER,
    updated_at INTEGER
);

CREATE TABLE workout_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workout_id INTEGER NOT NULL,
    exercise_id INTEGER NOT NULL,
    set_number INTEGER NOT NULL,
    reps INTEGER,
    weight REAL,
    completed_at INTEGER,
    created_at INTEGER,
    updated_at INTEGER,
    FOREIGN KEY (workout_id) REFERENCES workouts(id) ON DELETE CASCADE,
    FOREIGN KEY (exercise_id) REFERENCES exercises(id)
);

CREATE TABLE routines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    created_at INTEGER,
    updated_at INTEGER
);

CREATE TABLE routine_exercises (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    routine_id INTEGER NOT NULL,
    exercise_id INTEGER NOT NULL,
    order_index INTEGER DEFAULT 0,
    target_sets INTEGER,
    target_reps INTEGER,
    target_weight REAL,
    created_at INTEGER,
    updated_at INTEGER,
    FOREIGN KEY (routine_id) REFERENCES routines(id) ON DELETE CASCADE,
    FOREIGN KEY (exercise_id) REFERENCES exercises(id)
);

CREATE TABLE goals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    target_value REAL,
    current_value REAL,
    unit TEXT,
    deadline INTEGER,
    created_at INTEGER,
    updated_at INTEGER
);

CREATE TABLE cardio_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_type TEXT NOT NULL DEFAULT 'bike',
    duration_minutes INTEGER NOT NULL DEFAULT 15,
    calories_burned INTEGER,
    heart_rate_avg INTEGER,
    resistance_level INTEGER,
    notes TEXT,
    completed_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX idx_workouts_user ON workouts(user_id, ended_at, started_at);
CREATE INDEX idx_sets_workout ON workout_sets(workout_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

INSERT INTO users (id, name, email, password, created_at, updated_at)
VALUES (1, 'Meep', 'meep@workout.local', '$argon2id$v=19$m=19456,t=2,p=1$1E7WedFR+9k2E5ZYFh/0vw$bxBZQ3KnkHIzqye4IgN/sGBXobXQoonOv/uDfBtz7Hs', 1700000000000, 1700000000000);

INSERT INTO exercises (name, category, created_at, updated_at) VALUES
('Arm Curl','Arms',1700000000000,1700000000000),
('Back Extension','Back',1700000000000,1700000000000),
('Barbell Row','Back',1700000000000,1700000000000),
('Bench Press','Chest',1700000000000,1700000000000),
('Bicep Curl','Arms',1700000000000,1700000000000),
('Calf Raise','Legs',1700000000000,1700000000000),
('Chest Press','Chest',1700000000000,1700000000000),
('Converging Chest Press','Chest',1700000000000,1700000000000),
('Crunch','Core',1700000000000,1700000000000),
('Curl','Arms',1700000000000,1700000000000),
('Curl Alt','Arms',1700000000000,1700000000000),
('Deadlift','Back',1700000000000,1700000000000),
('Decline Press','Chest',1700000000000,1700000000000),
('Dip','Chest',1700000000000,1700000000000),
('Diverging Lat Pulldown','Back',1700000000000,1700000000000),
('Diverging Seated Row','Back',1700000000000,1700000000000),
('Dumbbell Fly','Chest',1700000000000,1700000000000),
('Extension','Other',1700000000000,1700000000000),
('Extension Alt','Other',1700000000000,1700000000000),
('Face Pull','Shoulders',1700000000000,1700000000000),
('Fly','Chest',1700000000000,1700000000000),
('Forearm Curl','Arms',1700000000000,1700000000000),
('Hack Squat','Legs',1700000000000,1700000000000),
('Hammer Curl','Arms',1700000000000,1700000000000),
('Incline Bench Press','Chest',1700000000000,1700000000000),
('Lat Pulldown','Back',1700000000000,1700000000000),
('Lateral Raise','Shoulders',1700000000000,1700000000000),
('Leg Curl','Legs',1700000000000,1700000000000),
('Leg Extension','Legs',1700000000000,1700000000000),
('Leg Press','Legs',1700000000000,1700000000000),
('Low Back - Roc It','Back',1700000000000,1700000000000),
('Lunge','Legs',1700000000000,1700000000000),
('Lunges','Legs',1700000000000,1700000000000),
('MTS High Row','Back',1700000000000,1700000000000),
('Overhead Press','Shoulders',1700000000000,1700000000000),
('Pec Fly','Chest',1700000000000,1700000000000),
('Plank','Core',1700000000000,1700000000000),
('Plank Hold','Core',1700000000000,1700000000000),
('Preacher Curl','Arms',1700000000000,1700000000000),
('Pull','Back',1700000000000,1700000000000),
('Pull Up','Back',1700000000000,1700000000000),
('Raise','Shoulders',1700000000000,1700000000000),
('Romanian Deadlift','Legs',1700000000000,1700000000000),
('Rotary Torso','Core',1700000000000,1700000000000),
('Seated Dip','Chest',1700000000000,1700000000000),
('Shoulder Press','Shoulders',1700000000000,1700000000000),
('Shoulder Press - Machine','Shoulders',1700000000000,1700000000000),
('Shrug','Shoulders',1700000000000,1700000000000),
('Shrugs','Shoulders',1700000000000,1700000000000),
('Skull Crusher','Arms',1700000000000,1700000000000),
('Squat','Legs',1700000000000,1700000000000),
('Tire Flip','Other',1700000000000,1700000000000),
('Tire Flips','Other',1700000000000,1700000000000),
('Tire Squat','Legs',1700000000000,1700000000000),
('Tire Squats','Legs',1700000000000,1700000000000),
('Tricep Extensions','Arms',1700000000000,1700000000000),
('Tricep Pushdown','Arms',1700000000000,1700000000000),
('Twist','Core',1700000000000,1700000000000);

INSERT INTO routines (id, user_id, name, description, created_at, updated_at)
VALUES (1, 1, 'Upper Pull Day', 'Back and biceps workout', 1700000000000, 1700000000000);

INSERT INTO routine_exercises (routine_id, exercise_id, order_index, target_sets, target_reps, target_weight, created_at, updated_at) VALUES
(1, 2, 1, 3, 10, 130, 1700000000000, 1700000000000),
(1, 16, 2, 3, 10, 70, 1700000000000, 1700000000000),
(1, 26, 3, 3, 10, 70, 1700000000000, 1700000000000),
(1, 5, 4, 3, 10, 45, 1700000000000, 1700000000000);
