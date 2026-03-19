# Integration Guide for NEXUS API and NEXUS Core

## Class Names and Imports

The exact class names and import paths for the NEXUS Core components are not available. Please follow the steps below to manually integrate the NEXUS API with the NEXUS Core.

## Steps to Activate NEXUS Online

1. **Edit `nexus_service.py`:**
   - Locate the `initialize` method in the `NexusService` class.
   - Replace the placeholder imports with the actual class names and import paths from the NEXUS Core.

   ```python
   async def initialize(self) -> None:
       nexus_root = Path(self.settings.NEXUS_CORE_PATH).resolve()
       bw_root    = nexus_root.parent
       for p in [str(bw_root), str(nexus_root)]:
           if p not in sys.path:
               sys.path.insert(0, p)
       try:
           # Replace with actual imports
           # from nexus_core.core.orchestrator import <OrchClass>
           # from nexus_core.core.planner import <PlanClass>
           # from nexus_core.agents.registry import <RegClass>

           # Instantiate with actual arguments
           # self._orch    = <OrchClass>(...)
           # self._planner = <PlanClass>(orch=self._orch, ...)
           # self._registry = <RegClass>()
           # self._initialized = True
           # self._mode = "online"
           # logger.info("NEXUS initialized in ONLINE mode")

           logger.warning("Auto-integration pending — activate real imports in nexus_service.py")
           self._mode = "offline"
       except ImportError as e:
           logger.warning(f"NEXUS import failed: {e} — OFFLINE mode")
           self._mode = "offline"
   ```

2. **Determine Class Names and Import Paths:**
   - Consult the NEXUS Core documentation or source code to find the exact class names and their respective modules.
   - Update the import statements in `nexus_service.py` accordingly.

3. **Validate Changes:**
   - After making the changes, validate the `nexus_service.py` file to ensure there are no syntax errors.

4. **Testing:**
   - Run the NEXUS API and verify that it operates in ONLINE mode without errors.

## Example

To activate NEXUS online, edit `nexus_service.py` at line 34 and replace the placeholder imports with the actual class names and import paths. Uncomment the instantiation lines and provide the necessary arguments.

---

This guide provides the necessary steps to manually integrate the NEXUS API with the NEXUS Core. Ensure you have access to the NEXUS Core documentation or source code to complete the integration.
