defmodule Server do
  use Application

  def start(_type, _args) do
    children = [
      Server.Server,
      {DynamicSupervisor, strategy: :one_for_one, name: Server.ClientSupervisor}]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
