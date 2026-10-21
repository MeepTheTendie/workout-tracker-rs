mod auth;
mod db;
mod handlers;
mod html;
mod progression;
mod types;

use worker::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let mut router = Router::new();

    // Auth
    router = router.get_async("/login", handlers::login_get);
    router = router.post_async("/action/auth/login", handlers::login_post);
    router = router.post_async("/action/auth/logout", handlers::logout_post);
    router = router.get_async("/change-password", handlers::change_password_get);
    router = router.post_async("/action/auth/change-password", handlers::change_password_post);

    // Dashboard
    router = router.get_async("/dashboard", handlers::dashboard_get);

    // Workouts
    router = router.get_async("/workouts/log", handlers::workouts_log_get);
    router = router.get_async("/workouts/history", handlers::workouts_history_get);
    router = router.get_async("/workouts/view", handlers::workouts_view_get);
    router = router.post_async("/action/workouts/start", handlers::workout_start_post);
    router = router.post_async("/action/workouts/add-set", handlers::add_set_post);
    router = router.post_async("/action/workouts/complete-set", handlers::complete_set_post);
    router = router.post_async("/action/workouts/edit-set", handlers::edit_set_post);
    router = router.post_async("/action/workouts/finish", handlers::finish_post);
    router = router.post_async("/action/workouts/remove-exercise", handlers::remove_exercise_post);
    router = router.post_async("/action/workouts/update-name", handlers::update_name_post);

    // Routines
    router = router.get_async("/routines", handlers::routines_list_get);
    router = router.get_async("/routines/create", handlers::routines_create_get);
    router = router.get_async("/routines/edit", handlers::routines_edit_get);
    router = router.post_async("/action/routines/create", handlers::routines_create_post);
    router = router.post_async("/action/routines/update", handlers::routines_update_post);
    router = router.post_async("/action/routines/delete", handlers::routines_delete_post);
    router = router.post_async("/action/routines/start", handlers::routines_start_post);
    router = router.post_async("/action/routines/add-exercise", handlers::routines_add_exercise_post);
    router = router.post_async("/action/routines/remove-exercise", handlers::routines_remove_exercise_post);
    router = router.post_async("/action/routines/update-exercise-targets", handlers::routines_update_targets_post);
    router = router.post_async("/action/routines/apply-progression", handlers::apply_progression_post);

    // Stats / Goals / PRs / Cardio / Export
    router = router.get_async("/stats", handlers::stats_get);
    router = router.get_async("/goals", handlers::goals_get);
    router = router.post_async("/action/goals/save", handlers::goals_save_post);
    router = router.post_async("/action/goals/delete", handlers::goals_delete_post);
    router = router.get_async("/prs", handlers::prs_get);
    router = router.get_async("/cardio", handlers::cardio_get);
    router = router.post_async("/action/cardio/add", handlers::cardio_add_post);
    router = router.get_async("/export", handlers::export_get);

    // Root
    router = router.get_async("/", |req, ctx| async move {
        let env = ctx.env.clone();
        if auth::current_user_id(&req, &env).await.unwrap_or(None).is_some() {
            let mut r = Response::empty()?.with_status(302);
            r.headers_mut().set("Location", "/dashboard")?;
            Ok(r)
        } else {
            let mut r = Response::empty()?.with_status(302);
            r.headers_mut().set("Location", "/login")?;
            Ok(r)
        }
    });

    // 404 fallback
    router = router.get_async("/*path", handlers::not_found);

    router.run(req, env).await
}
