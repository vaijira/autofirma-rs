use std::{cell::RefCell, collections::HashMap, rc::Rc};

use afirma_core::job::{Job, JobOutput, Request, Response, WorkerEvent};
use anyhow::{Result, anyhow};
use futures::channel::oneshot;
use wasm_bindgen::{JsCast, prelude::*};
use web_sys::{MessageEvent, Worker, WorkerOptions, WorkerType};

/// Path of the worker module built by rollup from `crates/afirma-worker`.
const WORKER_URL: &str = "js/worker.js";

#[derive(Default)]
struct State {
    next_id: u32,
    /// Requests waiting for their response, by id.
    pending: HashMap<u32, oneshot::Sender<Response>>,
    /// Messages sent before the worker announced [`WorkerEvent::Ready`];
    /// `None` once it is ready.
    queue: Option<Vec<JsValue>>,
}

/// Runs [`Job`]s in a Web Worker so heavy work does not block the UI.
pub struct WorkerClient {
    worker: Worker,
    state: Rc<RefCell<State>>,
    _onmessage: Closure<dyn Fn(MessageEvent)>,
}

impl std::fmt::Debug for WorkerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state.borrow();
        f.debug_struct("WorkerClient")
            .field("pending", &state.pending.len())
            .field("ready", &state.queue.is_none())
            .finish()
    }
}

impl WorkerClient {
    pub fn new() -> Result<Rc<Self>, JsValue> {
        let options = WorkerOptions::new();
        options.set_type(WorkerType::Module);
        let worker = Worker::new_with_options(WORKER_URL, &options)?;

        let state = Rc::new(RefCell::new(State {
            queue: Some(Vec::new()),
            ..State::default()
        }));
        let onmessage = Closure::<dyn Fn(MessageEvent)>::new({
            let state = state.clone();
            let worker = worker.clone();
            move |event: MessageEvent| match serde_wasm_bindgen::from_value::<WorkerEvent>(
                event.data(),
            ) {
                Ok(WorkerEvent::Ready) => {
                    let queued = state.borrow_mut().queue.take().unwrap_or_default();
                    for message in queued {
                        if let Err(err) = worker.post_message(&message) {
                            log::error!("Unable to post queued worker request: {err:?}");
                        }
                    }
                }
                Ok(WorkerEvent::Response(response)) => {
                    let sender = state.borrow_mut().pending.remove(&response.id);
                    if let Some(sender) = sender {
                        let _ = sender.send(response);
                    }
                }
                Err(err) => log::error!("Invalid worker message: {err}"),
            }
        });
        worker.set_onmessage(Some(onmessage.as_ref().unchecked_ref()));

        Ok(Rc::new(Self {
            worker,
            state,
            _onmessage: onmessage,
        }))
    }

    pub async fn run(&self, job: Job) -> Result<JobOutput> {
        let (sender, receiver) = oneshot::channel();
        let id = {
            let mut state = self.state.borrow_mut();
            state.next_id = state.next_id.wrapping_add(1);
            let id = state.next_id;
            state.pending.insert(id, sender);
            id
        };

        if let Err(err) = self.send(&Request { id, job }) {
            self.state.borrow_mut().pending.remove(&id);
            return Err(err);
        }

        let response = receiver
            .await
            .map_err(|_| anyhow!("El worker no respondió"))?;
        response.result.map_err(|e| anyhow!(e))
    }

    fn send(&self, request: &Request) -> Result<()> {
        let message = serde_wasm_bindgen::to_value(request).map_err(|e| anyhow!("{e}"))?;
        if let Some(queue) = &mut self.state.borrow_mut().queue {
            queue.push(message);
            return Ok(());
        }
        self.worker
            .post_message(&message)
            .map_err(|e| anyhow!("No se pudo enviar el trabajo al worker: {e:?}"))
    }
}

impl Drop for WorkerClient {
    fn drop(&mut self) {
        self.worker.terminate();
    }
}
