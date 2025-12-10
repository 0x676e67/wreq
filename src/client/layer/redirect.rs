//! Middleware for following redirections.

mod future;
mod layer;
mod policy;

use std::mem;

use http_body::Body;

pub use self::{
    layer::{FollowRedirect, FollowRedirectLayer},
    policy::{Action, Attempt, Policy},
};

enum BodyRepr<B> {
    Some(B),
    Empty,
    None,
}

impl<B> BodyRepr<B>
where
    B: Body + Default,
{
    fn take(&mut self) -> Option<B> {
        match mem::replace(self, BodyRepr::None) {
            BodyRepr::Some(body) => Some(body),
            BodyRepr::Empty => {
                *self = BodyRepr::Empty;
                Some(B::default())
            }
            BodyRepr::None => None,
        }
    }

    fn try_clone_from<P, E>(&mut self, body: &B, policy: &P)
    where
        P: Policy<B, E>,
    {
        match self {
            BodyRepr::Some(_) | BodyRepr::Empty => {}
            BodyRepr::None => {
                if body.size_hint().exact() == Some(0) {
                    *self = BodyRepr::Some(B::default());
                } else if let Some(cloned) = policy.clone_body(body) {
                    *self = BodyRepr::Some(cloned);
                }
            }
        }
    }
}
