/*
Las piezas con las que se dibujan las nueve sub-pestañas son las del kit de
formulario-de-panel, `ui/Ajustes`. Estaban aquí y, otra vez, en DHCP; ver allí
qué costó tenerlas dos veces.

Este fichero se queda como el punto por el que las nueve sub-pestañas las piden,
para no repetir la ruta en once ficheros.
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
