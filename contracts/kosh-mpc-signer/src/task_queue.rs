//! Generic task queue for coordinating on-chain/off-chain work between execution engines.
//!
//! Each task has a definition (what to compute) and collects completions from each engine.
//! Once all engines report, the task is marked complete and ready for the next phase.

use create_type_spec_derive::CreateTypeSpec;
use pbc_contract_common::avl_tree_map::AvlTreeMap;
use pbc_contract_common::off_chain::OffChainContext;
use pbc_traits::ReadWriteState;
use read_write_state_derive::ReadWriteState;

/// Unique identifier for a task within a queue.
pub type TaskId = u32;

/// Index of an execution engine (0, 1, or 2 for 3-engine setup).
pub type EngineIndex = u8;

/// A single task in the queue.
#[derive(ReadWriteState, CreateTypeSpec)]
pub struct Task<DefinitionT: ReadWriteState, CompletionT: ReadWriteState> {
    /// Unique task ID within this queue.
    pub task_id: TaskId,
    /// The task definition / input data.
    pub definition: DefinitionT,
    /// Completions reported by each engine (engine_index -> completion).
    pub completions: Vec<Option<CompletionT>>,
    /// Whether this task has been fully completed (all engines reported).
    pub completed: bool,
}

/// A queue of tasks coordinated between on-chain contract and off-chain engines.
#[derive(ReadWriteState, CreateTypeSpec)]
pub struct TaskQueue<DefinitionT: ReadWriteState, CompletionT: ReadWriteState> {
    /// Bucket ID for off-chain storage tracking of handled tasks.
    pub bucket_id: Vec<u8>,
    /// Number of engines that must complete each task.
    pub num_engines: EngineIndex,
    /// IDs of pending (not yet completed) tasks, in order.
    pub queue: Vec<TaskId>,
    /// Next task ID to assign.
    pub next_task_id: TaskId,
    /// All tasks (pending and completed).
    pub tasks: AvlTreeMap<TaskId, Task<DefinitionT, CompletionT>>,
}

impl<DefinitionT: ReadWriteState, CompletionT: ReadWriteState> TaskQueue<DefinitionT, CompletionT> {
    /// Create a new empty task queue.
    pub fn new(bucket_id: Vec<u8>, num_engines: EngineIndex) -> Self {
        Self {
            bucket_id,
            num_engines,
            queue: Vec::new(),
            next_task_id: 0,
            tasks: AvlTreeMap::new(),
        }
    }

    /// Push a new task onto the queue. Returns the assigned task ID.
    pub fn push_task(&mut self, definition: DefinitionT) -> TaskId {
        let task_id = self.next_task_id;
        self.next_task_id += 1;

        let mut completions = Vec::new();
        for _ in 0..self.num_engines {
            completions.push(None);
        }

        let task = Task {
            task_id,
            definition,
            completions,
            completed: false,
        };

        self.tasks.insert(task_id, task);
        self.queue.push(task_id);
        task_id
    }

    /// Record a completion from an engine for a specific task.
    /// Returns true if all engines have now completed this task.
    pub fn mark_completed_by_engine(
        &mut self,
        engine_index: EngineIndex,
        task_id: TaskId,
        completion: CompletionT,
    ) -> bool {
        let mut task = self.tasks.get(&task_id).expect("Task not found");
        assert!(
            !task.completed,
            "Task {} already completed",
            task_id
        );
        assert!(
            (engine_index as usize) < task.completions.len(),
            "Invalid engine index"
        );
        assert!(
            task.completions[engine_index as usize].is_none(),
            "Engine {} already reported for task {}",
            engine_index,
            task_id
        );

        task.completions[engine_index as usize] = Some(completion);

        // Check if all engines have reported
        let all_complete = task.completions.iter().all(|c| c.is_some());
        if all_complete {
            task.completed = true;
            // Remove from pending queue
            self.queue.retain(|id| *id != task_id);
        }

        self.tasks.insert(task_id, task);
        all_complete
    }

    /// Mark a task as complete without engine completions (for cancellation).
    pub fn mark_completion(&mut self, task_id: TaskId) {
        let mut task = self.tasks.get(&task_id).expect("Task not found");
        task.completed = true;
        self.tasks.insert(task_id, task);
        self.queue.retain(|id| *id != task_id);
    }

    /// Cancel all pending tasks.
    pub fn cancel_all_pending_tasks(&mut self) {
        let pending_ids: Vec<TaskId> = self.queue.clone();
        for task_id in pending_ids {
            self.mark_completion(task_id);
        }
    }

    /// Check if there are pending tasks in the queue.
    pub fn has_pending_tasks(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Get the next pending task ID, if any.
    pub fn next_pending_task_id(&self) -> Option<TaskId> {
        self.queue.first().copied()
    }

    /// Get a task by ID.
    pub fn get_task(&self, task_id: &TaskId) -> Option<Task<DefinitionT, CompletionT>> {
        self.tasks.get(task_id)
    }

    /// Get the next unhandled task for an off-chain engine.
    /// Uses off-chain storage to track which tasks this engine has already processed.
    pub fn next_unhandled(
        &self,
        ctx: &mut OffChainContext,
    ) -> Option<Task<DefinitionT, CompletionT>> {
        let mut handled_storage: pbc_contract_common::off_chain::OffChainStorage<TaskId, u8> =
            ctx.storage(&self.bucket_id);

        for task_id in &self.queue {
            if handled_storage.get(task_id).is_none() {
                handled_storage.insert(*task_id, 1);
                return self.tasks.get(task_id);
            }
        }
        None
    }

    /// Get multiple unhandled tasks (up to `limit`) for batch processing.
    pub fn next_multiple_unhandled(
        &self,
        ctx: &mut OffChainContext,
        limit: usize,
    ) -> Vec<Task<DefinitionT, CompletionT>> {
        let mut handled_storage: pbc_contract_common::off_chain::OffChainStorage<TaskId, u8> =
            ctx.storage(&self.bucket_id);
        let mut result = Vec::new();

        for task_id in &self.queue {
            if result.len() >= limit {
                break;
            }
            if handled_storage.get(task_id).is_none() {
                handled_storage.insert(*task_id, 1);
                if let Some(task) = self.tasks.get(task_id) {
                    result.push(task);
                }
            }
        }
        result
    }

    /// Report completion from off-chain by sending a transaction to the contract.
    pub fn report_completion<F>(
        &self,
        ctx: &mut OffChainContext,
        task: &Task<DefinitionT, CompletionT>,
        rpc_generator: F,
        completion: CompletionT,
        gas: u64,
    ) where
        F: Fn(TaskId, CompletionT) -> Vec<u8>,
    {
        let rpc = rpc_generator(task.task_id, completion);
        ctx.send_transaction_to_contract(rpc, gas);
    }

    /// Report multiple completions in a single batch transaction.
    pub fn report_completion_batched<F>(
        &self,
        ctx: &mut OffChainContext,
        rpc_generator: F,
        task_completions: Vec<(TaskId, CompletionT)>,
        gas: u64,
    ) where
        F: Fn(Vec<(TaskId, CompletionT)>) -> Vec<u8>,
    {
        if !task_completions.is_empty() {
            let rpc = rpc_generator(task_completions);
            ctx.send_transaction_to_contract(rpc, gas);
        }
    }
}
