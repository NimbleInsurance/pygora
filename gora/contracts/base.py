from algopy import (
    ARC4Contract,
    Application,
    TemplateVar,
    Asset,
    subroutine,
    Txn,
    Global,
    op,
    arc4,
    UInt64,
    Bytes,
    Account,
    String,
    itxn,
    OnCompleteAction,
    TransactionType,
)
from algopy.op import *

from typing import Literal as L


# ABI method argument specs to build signatures for oracle method calls.
request_method_spec = "(byte[],byte[],uint64,byte[],uint64[],uint64[],address[],(byte[],uint64)[])void"
response_method_spec = "(uint32[],byte[])void"

# ARC-4 type definitions for oracle specifications
class SourceSpec(arc4.Struct):
    """Oracle source specification for classic (type #1) requests."""
    source_id: arc4.UInt32
    source_arg_list: arc4.DynamicArray[arc4.DynamicBytes]
    max_age: arc4.UInt32

class SourceSpecUrl(arc4.Struct):
    """Oracle source specification for General URL (type #2) requests."""
    url: arc4.DynamicBytes
    auth_url: arc4.DynamicBytes
    value_expr: arc4.DynamicBytes
    timestamp_expr: arc4.DynamicBytes
    max_age: arc4.UInt32
    value_type: arc4.UInt8
    round_to: arc4.UInt8
    gateway_url: arc4.DynamicBytes
    reserved_0: arc4.DynamicBytes
    reserved_1: arc4.DynamicBytes
    reserved_2: arc4.UInt32
    reserved_3: arc4.UInt32

class SourceSpecOffChain(arc4.Struct):
    """
    Oracle source specification for off-chain (type #3) requests.

    api_version (arc4.UInt32): Minimum off-chain API version required
    spec_type (arc4.UInt8): executable specification type:
                            0 - in-place code,
                            1 - storage box (8-byte app ID followed by box name)
                            2 - URL
    exec_args (arc4.DynamicBytes): input arguments
    reserved_0..4: reserved for future use
    """
    api_version: arc4.UInt32
    spec_type: arc4.UInt8
    exec_spec: arc4.DynamicBytes
    exec_args: arc4.DynamicArray[arc4.DynamicBytes]
    reserved_0: arc4.DynamicBytes
    reserved_1: arc4.DynamicBytes
    reserved_2: arc4.UInt32
    reserved_3: arc4.UInt32

class RequestSpec(arc4.Struct):
    """Oracle classic (type #1) request specification."""
    source_specs: arc4.DynamicArray[SourceSpec]
    aggregation: arc4.UInt32
    user_data: arc4.DynamicBytes

class RequestSpecUrl(arc4.Struct):
    """Oracle General URL (type #2) request specification."""
    source_specs: arc4.DynamicArray[SourceSpecUrl]
    aggregation: arc4.UInt32
    user_data: arc4.DynamicBytes

class RequestSpecOffChain(arc4.Struct):
    """Oracle off-chain (type #3) request specification."""
    source_specs: arc4.DynamicArray[SourceSpecOffChain]
    aggregation: arc4.UInt32
    user_data: arc4.DynamicBytes

class DestinationSpec(arc4.Struct):
    """Specification of destination called by the oracle when returning data."""
    app_id: arc4.UInt64
    method: arc4.DynamicBytes

class ResponseBody(arc4.Struct):
    """Oracle response body."""
    request_id: arc4.StaticArray[arc4.Byte, L[32]]
    requester_addr: arc4.Address
    oracle_value: arc4.DynamicBytes
    user_data: arc4.DynamicBytes
    error_code: arc4.UInt32
    source_errors: arc4.UInt64

class BoxType(arc4.Struct):
    """Storage box specification."""
    key: arc4.DynamicBytes
    app_id: arc4.UInt64

"""
Base class for Gora-enabled Algorand Python contracts.
"""
class GoraContract(ARC4Contract):
    """
    Base Gora contract that provides oracle integration capabilities.
    Extends ARC4Contract to provide ABI method routing and oracle response handling.
    """
    
    def __init__(self) -> None:
        super().__init__()

        self.gora_main_app_id = TemplateVar[UInt64]("GORA_APP_ID") #GORA_MAIN_APP_ID")
        #self.main_app_addr = Bytes.from_hex(TemplateVar[str]("GORA_MAIN_APP_ADDR"))
    
    @arc4.abimethod
    def init_gora(self, token_ref: Asset, main_app_ref: Application) -> None:
        """Initialize the contract for Gora oracle integration."""
        # Ensure only creator can initialize
        assert Txn.sender == Global.creator_address
        
        # Opt into the Gora token
        itxn.AssetTransfer(
            xfer_asset=token_ref,
            asset_receiver=Global.current_application_address,
            asset_amount=UInt64(0)
        ).submit()
        
        # Opt into the main Gora application
        itxn.ApplicationCall(
            app_id=main_app_ref,
            on_completion=OnCompleteAction.OptIn
        ).submit()

    @subroutine
    def auth_dest_call(self) -> None:
        """Confirm that current call to a destination app is coming from Gora."""
        # Claude's version doesn't build, so replacing with something that does
        # caller_creator = op.AppParamsGet.creator(Global.caller_app_id)[1]
        caller_creator = Application(Global.caller_application_id).creator
        assert caller_creator == Application(self.gora_main_app_id).address
        # assert caller_creator == Bytes(main_app_info["addr_bin"])
        # Claude originally translated as #Bytes.from_hex(main_app_info["addr_bin"].hex());
        # confirming that the modified version is correct before purging.

    @subroutine
    def smart_assert(self, condition: bool, error_code: UInt64) -> None:
        """Assert with error code for debugging.
        Possibly delete (as obsolete) after completing testing of the migration.
        """
        if not condition:
            # Use a divide by zero to trigger an error with the code
            op.divw(0, UInt64(0), error_code)

    @subroutine 
    def oracle_request(
            self,
            request_type: UInt64,
            request_key: Bytes,
            request_spec_encoded: Bytes,
            dest_app: UInt64,
            dest_method: Bytes,
            box_refs: arc4.DynamicArray[BoxType],
            app_refs: arc4.DynamicArray[arc4.UInt64],
            asset_refs: arc4.DynamicArray[arc4.UInt64],
            account_refs: arc4.DynamicArray[arc4.Address]
    ) -> None:
        """Make an oracle request with specified parameters."""
        
        if dest_app==UInt64(0):
            # If dest app unspecified, make call reflexive
            dest_app = Global.current_application_id.id
            
        # Create destination specification
        dest_spec = DestinationSpec(
            app_id=arc4.UInt64(dest_app),
            method=arc4.DynamicBytes.from_bytes(dest_method)
        )
        
        # Submit oracle request via inner transaction
        itxn.ApplicationCall(
            app_id=self.gora_main_app_id,
            app_args=(
                Bytes(b"request"),  # Method selector
                request_spec_encoded,
                dest_spec.bytes,
                op.itob(request_type),
                request_key,
                app_refs.bytes,
                asset_refs.bytes, 
                account_refs.bytes,
                box_refs.bytes
            )
        ).submit()

    @subroutine
    def query_general_url(
            self,
            request_key: Bytes,
            dest_app: UInt64, 
            dest_method: Bytes,
            url: Bytes,
            value_expr: Bytes,
            aggregation: UInt64,
            timestamp_expr: Bytes,
            max_age: UInt64,
            auth_url: Bytes,
            gateway_url: Bytes,
            value_type: UInt64,
            round_to: UInt64,
            user_data: Bytes,
    ) -> None:
        """Make a General URL request with URL source."""
        
        # Create URL source specification
        source_spec = SourceSpecUrl(
            url=arc4.DynamicBytes.from_bytes(url),
            auth_url=arc4.DynamicBytes.from_bytes(auth_url),
            value_expr=arc4.DynamicBytes.from_bytes(value_expr), 
            timestamp_expr=arc4.DynamicBytes.from_bytes(timestamp_expr),
            max_age=arc4.UInt32(max_age),
            value_type=arc4.UInt8(value_type),
            round_to=arc4.UInt8(round_to),
            gateway_url=arc4.DynamicBytes.from_bytes(gateway_url),
            reserved_0=arc4.DynamicBytes.from_bytes(Bytes(b"")),
            reserved_1=arc4.DynamicBytes.from_bytes(Bytes(b"")),
            reserved_2=arc4.UInt32(0),
            reserved_3=arc4.UInt32(0)
        )
        
        # Create request specification
        request_spec = RequestSpecUrl(
            source_specs=arc4.DynamicArray[SourceSpecUrl](source_spec.copy()),
            aggregation=arc4.UInt32(aggregation),
            user_data=arc4.DynamicBytes.from_bytes(user_data)
        )
        
        # Submit oracle request
        self.oracle_request(
            request_type=UInt64(2),
            request_key=request_key,
            request_spec_encoded=request_spec.bytes,
            dest_app=dest_app,
            dest_method=dest_method,
            box_refs=arc4.DynamicArray[BoxType](),
            app_refs=arc4.DynamicArray[arc4.UInt64](),
            asset_refs=arc4.DynamicArray[arc4.UInt64](),
            account_refs=arc4.DynamicArray[arc4.Address]()
        )

    @subroutine
    def query_off_chain(
            self,
            request_key: Bytes,
            dest_app: UInt64,
            dest_method: Bytes,
            api_version: UInt64,
            spec_type: UInt64,
            exec_spec: Bytes,
            exec_args: arc4.DynamicArray[arc4.DynamicBytes],
            user_data: Bytes
    ) -> None:
        """Make an off-chain computation request."""
        
        # Create off-chain source specification
        source_spec = SourceSpecOffChain(
            api_version=arc4.UInt32(api_version),
            spec_type=arc4.UInt8(spec_type),
            exec_spec=arc4.DynamicBytes.from_bytes(exec_spec),
            exec_args=exec_args.copy(),
            reserved_0=arc4.DynamicBytes.from_bytes(Bytes(b"")),
            reserved_1=arc4.DynamicBytes.from_bytes(Bytes(b"")),
            reserved_2=arc4.UInt32(0),
            reserved_3=arc4.UInt32(0)
        )
        
        # Create request specification  
        request_spec = RequestSpecOffChain(
            source_specs=arc4.DynamicArray[SourceSpecOffChain](source_spec.copy()),
            aggregation=arc4.UInt32(0),
            user_data=arc4.DynamicBytes.from_bytes(user_data)
        )
        
        # Submit oracle request
        self.oracle_request(
            request_type=UInt64(3),
            request_key=request_key,
            request_spec_encoded=request_spec.bytes,
            dest_app=dest_app,
            dest_method=dest_method,
            box_refs=arc4.DynamicArray[BoxType](),
            app_refs=arc4.DynamicArray[arc4.UInt64](),
            asset_refs=arc4.DynamicArray[arc4.UInt64](),
            account_refs=arc4.DynamicArray[arc4.Address]()
        )

    @subroutine
    def query_classic(
            self,
            request_key: Bytes,
            dest_app: UInt64,
            dest_method: Bytes,
            source_id: UInt64,
            source_args: arc4.DynamicArray[arc4.DynamicBytes],
            max_age: UInt64,
            aggregation: UInt64,
            user_data: Bytes
    ) -> None:
        """Make a classic request with source ID."""
        
        # Create classic source specification
        source_spec = SourceSpec(
            source_id=arc4.UInt32(source_id),
            source_arg_list=source_args.copy(),
            max_age=arc4.UInt32(max_age)
        )
        
        # Create request specification
        request_spec = RequestSpec(
            source_specs=arc4.DynamicArray[SourceSpec](source_spec.copy()),
            aggregation=arc4.UInt32(aggregation),
            user_data=arc4.DynamicBytes.from_bytes(user_data)
        )
        
        # Submit oracle request
        self.oracle_request(
            request_type=UInt64(1),
            request_key=request_key,
            request_spec_encoded=request_spec.bytes,
            dest_app=dest_app,
            dest_method=dest_method,
            box_refs=arc4.DynamicArray[BoxType](),
            app_refs=arc4.DynamicArray[arc4.UInt64](),
            asset_refs=arc4.DynamicArray[arc4.UInt64](),
            account_refs=arc4.DynamicArray[arc4.Address]()
        )

    @subroutine
    def validate_oracle_response(
            self,
            resp_type: arc4.UInt32,
            resp_body_bytes: arc4.DynamicBytes
    ) -> ResponseBody:
        # Verify the call is coming from the Gora main application
        self.auth_dest_call()
        
        # Verify response type
        assert resp_type.native == 1
        
        # Decode response body
        return ResponseBody.from_bytes(resp_body_bytes.native)


# Export the main classes and functions
__all__ = [
    'GoraContract',
    # ARC-4 type definitions
    'SourceSpec',
    'SourceSpecUrl', 
    'SourceSpecOffChain',
    'RequestSpec',
    'RequestSpecUrl',
    'RequestSpecOffChain',
    'DestinationSpec',
    'ResponseBody',
    'BoxType',
]
