/*
The pieces the nine sub-tabs are drawn with are the panel-form kit's,
`ui/Ajustes`. They were here and, again, in DHCP; see there what having them
twice cost.

This file stays as the door through which the nine sub-tabs ask for them, so as
not to repeat the path in eleven files.
*/
export {
  AreaRow,
  Notices,
  Block,
  Check,
  Coletilla,
  EditableList,
  GroupRow,
  Help,
  Note,
  Plain,
  Pre,
  Radios,
  Row,
  TextRow,
  Warning,
  panelFormStyles,
  type Column,
  type RadioOption,
} from '../../ui/PanelForm'
export { default as settingsStyles } from './Settings.module.css'
