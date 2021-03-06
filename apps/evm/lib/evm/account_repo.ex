defmodule EVM.AccountRepo do
  alias Block.Header

  @moduledoc """
  Module that defines a set of functions to interact with accounts.
  """

  @type t :: struct()

  @callback account_exists?(t, EVM.address()) :: {t, boolean()}

  @callback empty_account?(t, EVM.address()) :: {t, boolean()}

  @callback account_balance(t, EVM.address()) :: {t, nil | EVM.Wei.t()}

  @callback transfer(t, EVM.address(), EVM.address(), integer()) :: t

  @callback account_code(t, EVM.address()) :: {t, nil | binary()}

  @callback account_nonce(t, EVM.address()) :: {t, integer()}

  @callback account_code_hash(t, EVM.address()) :: {t, binary() | nil}

  @callback increment_account_nonce(t, EVM.address()) :: t()

  @callback storage(t, EVM.address(), integer()) ::
              {t, {:ok, integer()} | :account_not_found | :key_not_found}

  @callback initial_storage(t, EVM.address(), integer()) ::
              {t, {:ok, integer()} | :account_not_found | :key_not_found}

  @callback put_storage(t, EVM.address(), integer(), integer()) :: t

  @callback remove_storage(t(), EVM.address(), integer()) :: t()

  @callback dump_storage(t) :: %{EVM.address() => EVM.val()}

  @callback create_contract(
              t,
              EVM.address(),
              EVM.address(),
              EVM.Gas.t(),
              EVM.Gas.gas_price(),
              EVM.Wei.t(),
              EVM.MachineCode.t(),
              integer(),
              Header.t(),
              EVM.address() | nil,
              EVM.Configuration.t()
            ) ::
              {:error, {t, EVM.Gas.t(), EVM.SubState.t(), <<>> | binary()}}
              | {:ok, {t, EVM.Gas.t(), EVM.SubState.t(), <<>>}}

  @doc "Sets the balance of the account at the given address to zero"
  @callback clear_balance(t, EVM.address()) :: t

  @spec repo(t) :: module()
  def repo(implementation) do
    implementation.__struct__
  end
end
