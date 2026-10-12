import {
  DOCKER_WRITE_ACTIONS,
  type DockerWriteAction,
} from "../shared/docker-write-contract";

const LABELS: Record<DockerWriteAction, string> = {
  start: "启动",
  stop: "停止",
  restart: "重启",
  pause: "暂停",
  unpause: "恢复运行",
  kill: "强制终止",
  remove: "删除",
};

export function dockerActionLabel(action: DockerWriteAction): string {
  return LABELS[action];
}

/**
 * How loudly a row button should read.
 *
 * Only the two that cannot be undone are marked: kill and remove. Stop is
 * reversible and start is not destructive at all, so colouring those too would
 * spend the one signal the row has on things that do not need it.
 */
export function dockerActionTone(action: DockerWriteAction): "danger" | "plain" {
  return action === "remove" || action === "kill" ? "danger" : "plain";
}


/**
 * Which actions make sense for a container in this state.
 *
 * This mirrors the planner's own state machine, and mirroring is all it is: an
 * action that slips through is refused at plan time, where the state is read
 * from the host again rather than taken from a row that may be minutes old.
 * Offering a button that cannot work is a worse experience than one fewer
 * button, which is the only reason this exists.
 */
/**
 * Whether a shell could be opened in a container in this state.
 *
 * Only a running container has a process namespace to enter. A paused one has
 * one, but every keystroke would block until it is unpaused, which reads as a
 * hung terminal — so it is not offered either.
 */
export function canOpenContainerShell(state: string): boolean {
  return state === "running";
}

export function availableDockerActions(state: string): readonly DockerWriteAction[] {
  return DOCKER_WRITE_ACTIONS.filter((action) => {
    switch (action) {
      case "start":
        return state === "created" || state === "exited" || state === "dead";
      case "stop":
      case "kill":
        return state === "running" || state === "paused" || state === "restarting";
      case "restart":
        return state === "running" || state === "paused";
      case "pause":
        return state === "running";
      case "unpause":
        return state === "paused";
      case "remove":
        return state === "created" || state === "removing" || state === "exited" ||
          state === "dead";
    }
  });
}
