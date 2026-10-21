use std::collections::HashMap;

pub fn suggest_next_weight(name: &str, last: Option<f64>) -> Option<f64> {
    let last = last?;
    let rules: &[(&str, i64, Option<i64>, Option<i64>)] = &[
        ("Hack Squat", 15, Some(200), Some(20)),
        ("Bench Press", 10, Some(150), Some(15)),
        ("Romanian Deadlift", 15, Some(135), Some(20)),
        ("Diverging Seated Row", 10, None, None),
        ("Leg Curl", 10, Some(100), Some(15)),
        ("Crunch", 5, None, None),
        ("Barbell Row", 10, Some(115), Some(15)),
        ("Lat Pulldown", 10, Some(130), Some(15)),
        ("Face Pull", 5, None, None),
        ("Bicep Curl", 5, Some(50), Some(10)),
        ("Low Back - Roc It", 15, Some(100), Some(20)),
        ("Tire Squats", 20, Some(400), Some(30)),
        ("Chest Press", 10, Some(150), Some(15)),
        ("Leg Extension", 10, Some(130), Some(15)),
        ("Seated Dip", 10, Some(130), Some(15)),
        ("Shrug", 10, Some(130), Some(15)),
        ("Sled Push", 10, None, None),
        ("Back Extension", 15, None, None),
        ("Leg Press", 15, None, None),
        ("Converging Chest Press", 15, None, None),
        ("Tricep Extensions", 10, None, None),
        ("Shoulder Press - Machine", 20, None, None),
    ];
    for (n, inc, thr, after) in rules {
        if *n == name {
            let mut increment = *inc as f64;
            if let (Some(t), Some(a)) = (thr, after) {
                if last >= *t as f64 {
                    increment = *a as f64;
                }
            }
            return Some(last + increment);
        }
    }
    Some(last)
}

pub fn progression_note(name: &str) -> &'static str {
    match name {
        "Hack Squat" => "+15 lbs (then +20 after 200)",
        "Bench Press" => "+10 lbs (then +15 after 150)",
        "Romanian Deadlift" => "+15 lbs (then +20 after 135)",
        "Diverging Seated Row" => "+10 lbs",
        "Leg Curl" => "+10 lbs (then +15 after 100)",
        "Crunch" => "+5 lbs or +5 reps",
        "Barbell Row" => "+10 lbs (then +15 after 115)",
        "Lat Pulldown" => "+10 lbs (then +15 after 130)",
        "Face Pull" => "+5 lbs or +5 reps",
        "Bicep Curl" => "+5 lbs (then +10 after 50)",
        "Low Back - Roc It" => "+15 lbs (then +20 after 100)",
        "Tire Squats" => "+20 lbs (then +30 after 400)",
        "Chest Press" => "+10 lbs (then +15 after 150)",
        "Leg Extension" => "+10 lbs (then +15 after 130)",
        "Seated Dip" => "+10 lbs (then +15 after 130)",
        "Shrug" => "+10 lbs (then +15 after 130)",
        "Sled Push" => "+10 lbs or +2 reps",
        "Back Extension" => "+15 lbs",
        "Leg Press" => "+15 lbs",
        "Converging Chest Press" => "+15 lbs",
        "Tricep Extensions" => "+10 lbs",
        "Shoulder Press - Machine" => "+20 lbs",
        _ => "",
    }
}

pub fn _unused() -> HashMap<String, i64> { HashMap::new() }
