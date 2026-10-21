use serde::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct UserRow {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ExerciseRow {
    pub id: i64,
    pub name: String,
    pub category: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct WorkoutRow {
    pub id: i64,
    pub user_id: i64,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub notes: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SetRow {
    pub id: i64,
    pub workout_id: i64,
    pub exercise_id: i64,
    pub set_number: i64,
    pub reps: Option<i64>,
    pub weight: Option<f64>,
    pub completed_at: Option<i64>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RoutineRow {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RoutineExerciseRow {
    pub id: i64,
    pub routine_id: i64,
    pub exercise_id: i64,
    pub order_index: Option<i64>,
    pub target_sets: Option<i64>,
    pub target_reps: Option<i64>,
    pub target_weight: Option<f64>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct GoalRow {
    pub id: i64,
    pub user_id: i64,
    pub title: String,
    pub target_value: Option<f64>,
    pub current_value: Option<f64>,
    pub unit: Option<String>,
    pub deadline: Option<i64>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct CardioRow {
    pub id: i64,
    pub user_id: i64,
    pub session_type: String,
    pub duration_minutes: i64,
    pub calories_burned: Option<i64>,
    pub heart_rate_avg: Option<i64>,
    pub resistance_level: Option<i64>,
    pub notes: Option<String>,
    pub completed_at: i64,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SessionRow {
    pub id: String,
    pub user_id: i64,
    pub csrf_token: String,
    pub expires_at: i64,
}
