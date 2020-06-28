defmodule Server.Server do
  require Logger
  use Task

  def start_link(_opts) do
    Task.start_link(__MODULE__, :listen, [])
  end

  def listen() do
    {:ok, listen_socket} = :gen_tcp.listen(3020, [:binary, active: :once, reuseaddr: true])

    Logger.info "Listening on port 3020."

    loop(listen_socket)
  end

  defp loop(listen_socket) do
    {:ok, socket} = :gen_tcp.accept(listen_socket)

    {:ok, pid} = DynamicSupervisor.start_child(Server.ClientSupervisor, {Server.Client, socket})
    :gen_tcp.controlling_process(socket, pid)

    loop(listen_socket)
  end
end
