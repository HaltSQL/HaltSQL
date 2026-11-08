// Mermaid's flowchart tooltips call `selection.transition()` on every node
// mouse-out. That method is added to d3 selections only as a side effect of
// importing d3-transition, and webpack drops that import because the `d3`
// package declares "sideEffects": false. Importing it here restores
// `.transition()` and stops "tooltipElem.transition is not a function".
import 'd3-transition';
