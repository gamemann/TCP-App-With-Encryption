defmodule Server.Client do
  require Logger
  use GenServer

  @initial_state %{state: :ident, socket: nil, counter: 1}

  def start_link(socket, opts \\ []) do
    GenServer.start_link(__MODULE__, socket, opts)
  end

  def init(socket) do
    stuff = @initial_state
    stuff = %{stuff | socket: socket}

    {:ok, stuff}
  end

  def handle_info({:tcp, socket, data}, %{counter: counter} = state) do
    serve(socket, counter, data)
    :inet.setopts(socket, [active: :once])

    {:noreply, Map.put(state, :counter, counter+1)}
  end

  def handle_info({:tcp_closed, _socket}, _state) do
    Logger.info "Connection closed by user."

    Process.exit(self(), :normal)
  end

  def handle_info({:tcp_error, _socket, reason}, _state) do
    Logger.info "Connection closed due to an error :: #{reason}"

    Process.exit(self(), :normal)
  end

  defp serve(_socket, counter, data) do
    case read_key() do
      {:ok, key} ->
        # Get cipher text.
        ctext = :binary.part(data, {8, byte_size(data) - 24})

        # Get the tag.
        tag = :binary.part(data, {byte_size(data), -16})

        # Get hash for nonce/IV.
        hash = :crypto.hash(:sha256, :binary.part(data, {0, 8}))

        # Create the nonce/IV and copy first 12 bytes for SHA256 hash.
        <<iv::binary-size(12)>> = :binary.part(hash, {0, 12})

        # AAD
        aad = <<>>

        # Attempt to decrypt message.
        decrypted = :crypto.crypto_one_time_aead(:chacha20_poly1305, key, iv, ctext, aad, tag, false)

        case decrypted do
          :error ->
            Logger.error "Error decrypting message."
            Logger.info "Key (#{byte_size(key)}) => #{Base.encode16(key)}"
            Logger.info "IV (#{byte_size(iv)}) => #{Base.encode16(iv)}"
            Logger.info "CText (#{byte_size(ctext)}) => #{Base.encode16(ctext)}"
            Logger.info "Tag (#{byte_size(tag)}) => #{Base.encode16(tag)}"
            Logger.info "Data (#{byte_size(data)}) => #{Base.encode16(data)}"
            Logger.info "Packet ##{counter}"

          _ ->
            Logger.info "Decrypted text => #{decrypted}"
        end

      :err ->
        Logger.error "Error getting key."
    end
  end

  defp read_key() do
    # Get keypath setting.
    keypath = Application.get_env(:server, :keypath, "/etc/tcpserver/key.txt")

    # Read key file and return results.
    case File.read(keypath) do
      {:ok, contents} ->
        {:ok, contents}

      {:error, msg} ->
        Logger.error "Error reading key file :: #{msg}"
        :err
    end
  end
end
