/*
The pieces the nine sub-tabs are drawn with are the panel-form kit's,
`ui/Ajustes`. They were here and, again, in DHCP; see there what having them
twice cost.

This file stays as the door through which the nine sub-tabs ask for them, so as
not to repeat the path in eleven files.
*/
export {
  AreaRow,
  Avisos,
  Block,
  Check,
  Coletilla,
  EditableTable,
  GroupRow,
  Help,
  Note,
  Plain,
  Pre,
  Radios,
  Row,
  TextRow,
  Warning,
  ajustesStyles,
  type Columna,
  type OpcionRadio,
} from '../../ui/Ajustes'
export { default as settingsStyles } from './Settings.module.css'
