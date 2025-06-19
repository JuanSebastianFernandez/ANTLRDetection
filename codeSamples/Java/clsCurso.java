package com.uc3m.codeSamples;

import clsModulo;
import java.util.ArrayList;

public class clsCurso {
	//ATRIBUTOS
	//atributos de clase
	private String nombre;
	private int semestre;
	private Calendar fechaInicio;
	//referencias y/o listados
	private ArrayList<clsEstudiante> lstEstudiantes;
	private ArrayList<clsModulo> lstModulos;
	private clsProfesor refProfesor;
	//METODOS
	//constructores
	public clsCurso(){
		this.lstEstudiantes = new ArrayList<clsEstudiante>();
		this.lstModulos = new ArrayList<clsModulo>();
	}
	public clsCurso(String nombre, int semestre, Calendar fechaInicio){
		this.nombre = nombre;
		this.semestre = semestre;
		this.fechaInicio = fechaInicio;
		this.lstEstudiantes = new ArrayList<clsEstudiante>();
		this.lstModulos = new ArrayList<clsModulo>();
	}
	//getters y setters
	public String getNombre() {
		return nombre;
	}
	public void setNombre(String nombre) {
		this.nombre = nombre;
	}
	public int getSemestre() {
		return semestre;
	}
	public void setSemestre(int semestre) {
		this.semestre = semestre;
	}
	public Calendar getFechaInicio() {
		return fechaInicio;
	}
	public void setFechaInicio(Calendar fechaInicio) {
		this.fechaInicio = fechaInicio;
	}
	public ArrayList<clsEstudiante> getLstEstudiantes() {
		return lstEstudiantes;
	}
	public void setLstEstudiantes(ArrayList<clsEstudiante> lstEstudiantes) {
		this.lstEstudiantes = lstEstudiantes;
	}
	public ArrayList<clsModulo> getLstModulos() {
		return lstModulos;
	}
	public void setLstModulos(ArrayList<clsModulo> lstModulos) {
		this.lstModulos = lstModulos;
	}	
	public clsProfesor getRefProfesor() {
		return refProfesor;
	}
	public void setRefProfesor(clsProfesor refProfesor) {
		this.refProfesor = refProfesor;
	}
	//metodos generales
	public void crearModulo(String tema, double porcentaje){
		clsModulo objM = new clsModulo(tema,porcentaje);
		this.lstModulos.add(objM); //curso agrega modulo
		objM.setRefCurso(this); //modulo agrega curso
		
	}
}
