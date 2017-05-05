/***************************************************************************/
/* Fichier: secu.c                                                         */
/* Ce fichier contient les routines de gestion de la securite operateur    */
/*                                                                         */
/* les messages lies a la securite et emis par canOpen sont rediriges vers */
/* le module secu pour validation et transfert a msCan.                    */
/* les messages lies a la securite recu par msCan sont controles et        */
/* peuvent etre egalement rediriges vers le module secu pour traitement    */
/*                                                                         */
/* Ecrit par: EB                                                           */
/***************************************************************************

VERSION:1.0  DATE: 27/09/07

modification history
--------------------
27/09/07 EB : version initiale
 */

/* module "seprologlib" */
#include <seprolog.h>

/* module "E2007_CanOpen" */
#include <canopen_secu.h>

#include "proto.h"

/********************** DEBUG ***********************/
#include <sys/neutrino.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <semaphore.h>

/* Globales */

static statusSecu_t inStatus;
static secuAdm_t    secuAdm;
static inSecu_t     inSecu;
static outSecu_t    outSecu;
fifoPlus_t *fifo_thread_vnc = NULL;
static int vnc_unsafe_mode = 0; /* 1 = indique qu'il ne faut pas filtre les "clicks" de VNC */

unsigned long       tul_Word[WORD_SIZE];          /* tableau des WORDs */
unsigned long      *ptTableau[finTypeDonnee];

static void activer_secu_carte_interface(secuLoc_t *secu);
static void demande_status_variateur(secuLoc_t *secu);
static int boucle_principal(secuLoc_t *pSecu);

/**
 * \brief demarrage du module
 * \param
 * \return
 */
int main(int argc, char *argv[])
{
	int retval = EXIT_FAILURE;
	int result = 0;
	secuLoc_t secu;
	char* pVersion;

	mlockall(MCL_CURRENT);
	pthread_setname_np(pthread_self(),"thread_principal");
	setvbuf (stdout, NULL, _IOLBF, 0);

	/*-----------------------*/
	/* Demarrage des process */
	/*-----------------------*/
	syncdem_etape(M_SECU);

	init_seprolog(M_SECU);

	pVersion = malloc(256);
	version_fb_gestMode(pVersion);
	slog(SLOG_INFO, pVersion);
	version_fb_inhibProtect(pVersion);
	slog(SLOG_INFO, pVersion);
	version_fb_gestStart(pVersion);
	slog(SLOG_INFO, pVersion);
	version_fb_gestInterverrou(pVersion);
	slog(SLOG_INFO, pVersion);
	version_fb_gestVnc(pVersion);
	slog(SLOG_INFO, pVersion);
	free(pVersion);

	optionsSecu(argc, argv);

	/*--------------------------*/
	/* Initialisation du Module */
	/*--------------------------*/
	memset(&secuAdm, 0, sizeof(secuAdm_t));
	memset(&inSecu, 0, sizeof(inSecu_t));
	memset(&outSecu, 0, sizeof(outSecu_t));
	memset(&secu, 0, sizeof(secuLoc_t));
	memset(&tul_Word[0], 0, sizeof(tul_Word));
	fifo_thread_vnc = fifoPlus_alloc(2, sizeof(display_mode_t));

	secu.sansPendant_old = TRUE;
	secu.sansPendant     = TRUE;

	/* attente de IHM et VNC-DISPLAY */
	syncdem_etape(M_SECU);

	result = initSecu(&secu);

	if (result == QNX_ERROR)
	{
		SrvDonnee_SetDefaut(&secu.connectServDonnees,D_MOD_SECU_PB_INIT,0,0);
		slog(SLOG_SHUTDOWN,"Initialisation error");
		goto out;
	}
	/*--------------------------------------------*/
	/* Initialisation des securites du module axe */
	/*--------------------------------------------*/
	secu.stopAxes = 0xFFFFFFFF;
	comm_moduleAxe(&secu, TIMEOUT_MODULE_AXE);

	/* attente que tous les autres modules soient prêts */
	syncdem_etape(M_SECU);

	/* secu demarre */
	retval = boucle_principal(&secu);

	out:
	/*
	 * TODO : arreter les threads (pthread_cancel), leurs laisser
	 * traiter leur arret (pthread_cleanup_push) et attendre
	 * leur arrets (pthread_join)
	 */

	/* securite attend pour s'arrêter */
	syncdem_etape(M_SECU);
	fifoPlus_free(fifo_thread_vnc);
	stop_seprolog();
	return retval;
}

/**
 * @brief demarre la tache secu de l'interface et attend qu'elle soit prete
 * @param secu pointeur sur les données du module SECU
 */
static void activer_secu_carte_interface(secuLoc_t *pSecu)
{
	int numInt;
	int result;
	canByte_t msgReq;
	bool ready=0;

	/*--------------------------------------------*/
	/* Active les securites de la carte Interface */
	/*--------------------------------------------*/
	pSecu->bitBauAux     = TRUE; /* entrees pas geree */
	pSecu->bitAuAux      = TRUE; /* entrees pas geree */
	pSecu->bitProtectAux = TRUE; /* entrees pas geree */
	pSecu->bauIhm        = TRUE; /* pour eviter un defaut au demarrage  */
	pSecu->ready         = TRUE; /* pour activer la secu de l'interface */

	for(numInt=0; numInt<MAX_INT_NUMBER && secuAdm.nodeInterface[numInt]; numInt++)
	{
		slog(SLOG_DEBUG1,"Wait Ready from Interface board %d/2 (node 0x%X)", numInt+1, secuAdm.nodeInterface[numInt]);
		do
		{
			pSecu->inputInt[numInt] = 0;   /* pour forcer l'envoi du pdo tant que l'interface n'est pas ready */
			result = comm_interface(pSecu, 30000); //30s
			if (result != 0)
				break;
			msgReq.trame.cob_id = 0x180 + secuAdm.nodeInterface[numInt];
			msgReq.trame.dlc = 0;
			msgReq.trame.rtr = 1;
			sendMsgCan(msgReq, secuAdm.busInterface[numInt], pSecu, TIMEOUT_DRIVER_CAN);
			delay (5);
			pthread_mutex_lock(&secuAdm.mutexSecu);
			ready = (bool)(inSecu.readyInt & (1 << numInt));
			pthread_mutex_unlock(&secuAdm.mutexSecu);
		}
		while (ready == FALSE);

		if (result == 0)
			slog(SLOG_DEBUG1,"The Interface board %d/2 (node 0x%X) is ready", numInt+1, secuAdm.nodeInterface[numInt]);
		else
			slog(SLOG_CRITICAL,"System error. No answer from Interface board %d/2 (node 0x%X)", numInt+1, secuAdm.nodeInterface[numInt]);
	}
}

/**
 * @brief demande le status des P3G3 pour determiner si les entrees STO doivent etre controlees
 * @param secu pointeur sur les données du module SECU
 */
static void demande_status_variateur(secuLoc_t *pSecu)
{
	int numCan;
	int numNode;
	int nodes;
	canByte_t msg;

	for(numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
	{
		nodes  = secuAdm.nodesSecu[numCan];
		while (nodes)
		{
			CNTLZW(numNode, nodes);
			if (numNode == -1)
				break;

			if ((secuAdm.typeNode[numCan][numNode] & TYP_VAR_CAN) == ID_INFRANOR)
			{
				msg.trame.cob_id  = 0x640 + numNode + 1;
				msg.trame.dlc     = 8;
				msg.trame.rtr     = 0;
				msg.trame.data[0] = 0x40;	/* initiate upload */
				msg.trame.data[1] = 0x20;	/* object 0x3020 */
				msg.trame.data[2] = 0x30;	/* object 0x3001 */
				msg.trame.data[3] = 0x00;	/* Sub-index 0x00 */
				msg.trame.data[4] = 0;
				msg.trame.data[5] = 0;
				msg.trame.data[6] = 0;
				msg.trame.data[7] = 0;

				sendMsgCan(msg, numCan, pSecu, TIMEOUT_DRIVER_CAN);
				slog(SLOG_DEBUG1,"upload object 0x3020-00 node = %d bus = %d", numNode+1, numCan);
				delay(10);
			}
			nodes &= ~(1 << numNode);
		}
	}
}

/**
 * @brief thread principal du module
 * @param pSecu pointeur sur les données du module SECU
 * @return EXIT_SUCCESS ou EXIT_FAILURE (sortie inattendue)
 */
static int boucle_principal(secuLoc_t *pSecu)
{
	int numCan;
	int numNode;
	int nodes;
	int popup=FALSE, questionPosee=FALSE;
	FB_GESTMODE gestMode;
	FB_INHIBPROTECT inhibProtect;
	FB_GESTSTART gestStart;
	FB_GESTINTERVERROU gestInterverrou;
	FB_GESTVNC gestVnc;
	statusSrvDonnee_t statusSrvDonnee;
	int cmpt_spi = 0;

	/*--------------------------------------------------*/
	/* Initialisation et active les securites de la CPU */
	/*--------------------------------------------------*/
	memset(&gestMode, 0, sizeof(FB_GESTMODE));
	memset(&inhibProtect, 0, sizeof(FB_INHIBPROTECT));
	memset(&gestStart, 0, sizeof(FB_GESTSTART));
	memset(&gestInterverrou, 0, sizeof(FB_GESTINTERVERROU));
	memset(&gestVnc, 0, sizeof(FB_GESTVNC));

	fb_gestMode(&gestMode);
	fb_inhibProtect(&inhibProtect);
	fb_gestStart(&gestStart);
	fb_gestInterverrou(&gestInterverrou);
	fb_gestVnc(&gestVnc);

	pSecu->activate = TRUE;
	pSecu->protectOkInt_old = 0;
	pSecu->protectOkInt = 0;
	pSecu->protectPresent = 0;
	pSecu->ihmHorsProtect = 0;

	pSecu->objetStoValide[0] = 0;
	pSecu->objetStoValide[1] = 0;
	pSecu->demEtatSto[0] = secuAdm.nodesSecu[0];
	pSecu->demEtatSto[1] = secuAdm.nodesSecu[1];

	/*--------------------------------------*/
	/* Connexion avec le serveur de donnees */
	/*--------------------------------------*/
	slog(SLOG_INFO,"Connection with Data Server");
	statusSrvDonnee = SrvDonnee_init(MOD_SECU,&pSecu->connectServDonnees,ptTableau);

	if (statusSrvDonnee.status != pasErreur)
	{
		slog(SLOG_CRITICAL,"Data server connection error");
		while(1)
			delay(1000);
	}
	/*----------------------------------------------------------------------*/
	/* On monte un defaut a la mise sous tension pour forcer l'acquittement */
	/*----------------------------------------------------------------------*/
	SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_MISE_SOUS_TENSION,0,0);

	/*------------------------------------------------------*/
	/* Initialisation du calcul de la periode de scrutation */
	/*------------------------------------------------------*/
	pSecu->timeThread = ClockCycles();
	pthread_mutex_lock(&secuAdm.mutexSecu);
	inSecu.timeSpi = ClockCycles();
	inSecu.timeStaubli = ClockCycles();
	pthread_mutex_unlock(&secuAdm.mutexSecu);

	/*-------------------------------------------------*/
	/* si des noeuds can sont configures non controles */
	/*-------------------------------------------------*/
	pthread_mutex_lock(&secuAdm.mutexSecu);
	if (inSecu.nodesUncontrolled[0] || inSecu.nodesUncontrolled[1])
	{
		SET_ERROR(SECU_CPU_ERROR, GEST_NODE, 0);
	}
	pthread_mutex_unlock(&secuAdm.mutexSecu);

	if (simu == FALSE)
	{
		/*--------------------------------*/
		/* Initialisation des filtres Can */
		/*--------------------------------*/
		pSecu->nodesPlugged[0] = 0xFFFFFFFF;
		pSecu->nodesPlugged[1] = 0xFFFFFFFF;
		configFiltre(pSecu);

		/*----------------------------------------*/
		/* demande le status des P3G3 via un SDO2 */
		/*----------------------------------------*/
		demande_status_variateur(pSecu);

		/*-------------------------------------------------------------------*/
		/* Active les fonctions de securite de l'interface et rearme le WDog */
		/*-------------------------------------------------------------------*/
		activer_secu_carte_interface(pSecu);
	}
	else
	{
		/*-----------------*/
		/* Mode Simulation */
		/*-----------------*/
		inSecu.validAxeInt   = 0xFFFFFFFF;
		inSecu.powerOkInt    = 0xFFFFFFFF;
		inSecu.vagvInt       = 0xFFFFFFFF;
		inSecu.protectOkInt  = 0xFFFFFFFF;
		inSecu.readyInt      = 0xFFFFFFFF;

		inSecu.ihmSurSupport = TRUE;
		inSecu.bauIhm        = TRUE;
	}

	/*-------------------*/
	/* Boucle principale */
	/*-------------------*/
	while(1)
	{
		/*------------------------------------------------------------------*/
		/* Attend le semaphore pour interdire la mise a jour des parametres */
		/*------------------------------------------------------------------*/
		sem_wait(&secuAdm.synchroParam);

		/*======================================*/
		/* Initialisation des variables locales */
		/*======================================*/
		pthread_mutex_lock(&secuAdm.mutexSecu);

		pSecu->demChgModesLoc        = inSecu.demChgModesLoc;
		pSecu->demChgModesExt        = inSecu.demChgModesExt;
		pSecu->nivModesEnCours       = inSecu.nivModesEnCours;
		pSecu->numDefEnCours         = inSecu.numDefEnCours;
		pSecu->demInhibProtect       = inSecu.demInhibProtect;
		pSecu->memDemChgInhibProtect = inSecu.memDemChgInhibProtect;
		pSecu->forceDeplacement      = inSecu.forceDeplacement;
		pSecu->sansPendant           = inSecu.sansPendant;
		pSecu->threadSpiStopped      = inSecu.threadSpiStopped;
		pSecu->puissanceIhm          = inSecu.puissanceIhm;
		pSecu->axesPlugged           = inSecu.axesPlugged;
		pSecu->nodesPlugged[0]       = inSecu.nodesPlugged[0];
		pSecu->nodesPlugged[1]       = inSecu.nodesPlugged[1];
		pSecu->nodesUncontrolled[0]  = inSecu.nodesUncontrolled[0];
		pSecu->nodesUncontrolled[1]  = inSecu.nodesUncontrolled[1];
		pSecu->etatInitNodes[0]      = inSecu.etatInitNodes[0];
		pSecu->etatInitNodes[1]      = inSecu.etatInitNodes[1];
		pSecu->bauIhm                = inSecu.bauIhm;
		pSecu->ihmSurSupport         = inSecu.ihmSurSupport;
		pSecu->bpValidG              = inSecu.bpValidG;
		pSecu->bpValidD              = inSecu.bpValidD;
		pSecu->numPopup              = inSecu.numPopup;
		pSecu->axesArretes           = inSecu.axesArretes;
		pSecu->prgSelectionne        = inSecu.prgSelectionne;
		pSecu->bitSansRobot          = inSecu.bitSansRobot;
		pSecu->demVerrouGache1 		 = inSecu.demVerrouGache1;
		pSecu->demVerrouGache2		 = inSecu.demVerrouGache2;

		pSecu->validAxeInt           = (inSecu.validAxeInt  == 0xFFFFFFFF);
		pSecu->powerOkInt            = (inSecu.powerOkInt   == 0xFFFFFFFF);
		pSecu->vagvInt               = (inSecu.vagvInt      == 0xFFFFFFFF);
		pSecu->protectOkInt          = (inSecu.protectOkInt == 0xFFFFFFFF);
		pSecu->ready                &= (inSecu.readyInt     == 0xFFFFFFFF);

		pSecu->execEnCours           = inSecu.execEnCours;
		pSecu->manuEnCours           = inSecu.manuEnCours;

		pSecu->timeSpi				 = inSecu.timeSpi;
		pSecu->timeStaubli			 = inSecu.timeStaubli;
		pSecu->powerOkStaubli		 = inSecu.powerOkStaubli;

		pSecu->stoInput[0]			 = inSecu.stoInput[0];
		pSecu->stoInput[1]			 = inSecu.stoInput[1];
		pSecu->objetStoValide[0]	 = inSecu.objetStoValide[0];
		pSecu->objetStoValide[1]	 = inSecu.objetStoValide[1];
		pSecu->puissanceOn[0]		 = inSecu.puissanceOn[0];
		pSecu->puissanceOn[1]		 = inSecu.puissanceOn[1];

		pSecu->demModeVnc			 = inSecu.demModeVnc;
		inSecu.demModeVnc            = -1;

		pthread_mutex_unlock(&secuAdm.mutexSecu);

		pthread_mutex_lock(&secuAdm.mutexStatus);
		memcpy(&pSecu->status, &inStatus, sizeof(statusSecu_t));
		pthread_mutex_unlock(&secuAdm.mutexStatus);

		/*==========================*/
		/* Traitement des securites */
		/*==========================*/
		pSecu->nivModes    = 0;
		pSecu->reset       = pSecu->acquitDefaut;
		pSecu->demChgModes = pSecu->demChgModesLoc;

		/*-------------------------------------------*/
		/* Controle du temps d'execution des threads */
		/*-------------------------------------------*/
		gest_thread(pSecu);

		/*---------------------------------*/
		/* Gestion de la connexion pendant */
		/*---------------------------------*/
		gest_sansPendant(pSecu);

		/*--------------------------------------------------*/
		/* Determine si le pendant est hors zone dangereuse */
		/*--------------------------------------------------*/
		gest_posPendant(pSecu, &gestInterverrou);

		/*---------------------------------*/
		/* Gestion de la commande deportee */
		/*---------------------------------*/
		gest_cdeDeportee(pSecu, &gestVnc);

		/*------------------*/
		/* Gestion du Start */
		/*------------------*/
		gest_start(pSecu, &gestStart);

		/*-------------------------*/
		/* Gestion du type d'arret */
		/*-------------------------*/
		gest_arret(pSecu);

		/*-----------------------------*/
		/* Gestion des modes de marche */
		/*-----------------------------*/
		gest_modes(pSecu, &gestMode);

		/*-----------------------------------------*/
		/* Gestion de l'inhibition des protecteurs */
		/*-----------------------------------------*/
		gest_inhibProtect(pSecu, &inhibProtect);

		/*---------------------------------------------------------------*/
		/* Controle de la communication avec l'IHM et la carte interface */
		/*---------------------------------------------------------------*/
		if (simu == FALSE)
			gest_wDog(pSecu);

		/*------------------------------------------*/
		/* Gestion des axes lors d'un arrêt de secu */
		/*------------------------------------------*/
		gest_ctrlAxes(pSecu, TIMEOUT_MODULE_AXE);

		/*----------------------------------------------------*/
		/* Controle l'etat du 24S lors d'un arret de securite */
		/*----------------------------------------------------*/
		gest_ctrl24S(pSecu);

		/*--------------------------*/
		/* Controle des entrees STO */
		/*--------------------------*/
		if (simu == FALSE)
			gest_ctrlSto(pSecu);

		/*--------------------------------------------------------*/
		/* Controle d'etat du Staubli lors d'un arret de securite */
		/*--------------------------------------------------------*/
		if (secuAdm.options.Axes.robot6x != sans6x)
			gest_ctrlStaubli(pSecu);

		/*=====================================*/
		/* Prise en compte des etats de sortie */
		/*=====================================*/
		pthread_mutex_lock(&secuAdm.mutexSecu);

		outSecu.puissanceIhm         = pSecu->puissanceIhm;
		outSecu.validAxeInt          = pSecu->validAxeInt;
		outSecu.forceDeplacement     = pSecu->forceDeplacement;
		outSecu.enInhibProtect       = pSecu->enInhibProtect;
		outSecu.nivModes             = pSecu->nivModes;
		outSecu.stopAxes             = pSecu->stopAxes;
		outSecu.nodesPlugged[0]      = pSecu->nodesPlugged[0];
		outSecu.nodesPlugged[1]      = pSecu->nodesPlugged[1];
		outSecu.nodesUncontrolled[0] = pSecu->nodesUncontrolled[0];
		outSecu.nodesUncontrolled[1] = pSecu->nodesUncontrolled[1];
		outSecu.sansPendant			 = pSecu->sansPendant;
		outSecu.reset				 = pSecu->reset;
		outSecu.modeVnc				 = pSecu->modeVnc;

		pthread_mutex_unlock(&secuAdm.mutexSecu);

		/*-------------------------------------------------------------------------*/
		/* Communication avec le serveur de donnees (Mise a jour des mots systeme) */
		/*-------------------------------------------------------------------------*/
		comm_servDonnee(pSecu, TIMEOUT_SERVDONNEE);

		/*---------------------------*/
		/* Communication avec le SPI */
		/*---------------------------*/
		if (cmpt_spi >= 1)
		{
			if (pSecu->threadSpiStopped == FALSE)
				sem_post(&secuAdm.semComSpi);

			cmpt_spi = 0;
		}
		else
			cmpt_spi++;

		/*-----------------------------*/
		/* Lancement de Exec ou Manuel */
		/*-----------------------------*/
		comm_moduleExecManu(pSecu);

		/*---------------------------------------*/
		/* Communication avec la carte Interface */
		/*---------------------------------------*/
		if (simu == FALSE)
			comm_interface(pSecu, TIMEOUT_DRIVER_CAN);

		/*----------------------------------*/
		/* Communication avec le module AXE */
		/*----------------------------------*/
		comm_moduleAxe(pSecu, TIMEOUT_MODULE_AXE);

		/*-----------------------------------*/
		/* Communication avec les variateurs */
		/*-----------------------------------*/
		if (simu == FALSE)
			comm_variateur(pSecu, TIMEOUT_DRIVER_CAN);

		/*----------------------------*/
		/* Communication avec staubli */
		/*----------------------------*/
		if (secuAdm.options.Axes.robot6x != sans6x)
			sem_post(&secuAdm.semStaubli);

		/*-----------------------------------------*/
		/* Communication avec VNC display et L'IHM */
		/*-----------------------------------------*/
		comm_vncDisplay();

		/*============================================*/
		/* Remontee des erreurs au serveur de donnees */
		/*============================================*/
		if (pSecu->status.defaut && pSecu->status.aTraiter)
		{
			switch (pSecu->status.type)
			{
			/*------------------------------------------------*/
			/* erreurs de communication et/ou erreurs systeme */
			/*------------------------------------------------*/
			case QNX_ERROR:
				SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_MOD_SECU_PB_UTIL_OBJ_SYSTEME,0,0);
				break;
			case SPI_ERROR:
			case MSCAN_ERROR:
			case EXEC_ERROR:
			case MANU_ERROR:
			case SERVDON_ERROR:
			case SECUCAN_ERROR:
			case AXE_ERROR:
			case STAUBLI_ERROR:
				SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_PB_DE_COMMUNICATION,0,0);
				break;
			case BUSCAN_ERROR:
				SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_PB_DE_COMMUNICATION_BUSCAN,pSecu->status.diagCode + 1,0);
				break;
				/*---------------------------------------------------------*/
				/* erreur generee par la carte Interface et les variateurs */
				/*---------------------------------------------------------*/
			case SECU_INT_ERROR:
			case SECU_VAR_ERROR:
				switch (pSecu->status.numFb)
				{
				case SECU_INTERFACE:
					slog(SLOG_WARNING,"The Interface board generated a error");
					/* le defaut est envoye au serveur de donnees par CanOpen */
					break;
				case GEST_EMERGENCY:
					for(numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
					{
						pthread_mutex_lock(&secuAdm.mutexSecu);
						nodes  = inSecu.emerError[numCan];
						pthread_mutex_unlock(&secuAdm.mutexSecu);
						nodes &= secuAdm.nodesSecu[numCan];
						nodes &= pSecu->nodesPlugged[numCan];

						/* tant qu'il existe des composants en erreur */
						while (nodes)
						{
							CNTLZW(numNode, nodes);
							if (numNode == -1)
								break;
							slog(SLOG_WARNING,"Node %d of CAN bus %d declared an emergency; Error code is 0x%08x",numNode+1, numCan, pSecu->status.diagCode);
							/* le defaut est envoye au serveur de donnees par CanOpen */
							break;
							nodes &= ~(1 << numNode);
						}
					}
					break;
				default:
					break;
				}
				break;
				/*----------------------------------------*/
				/* erreur generee par la carte auxiliaire */
				/*----------------------------------------*/
				case SECU_IHM_ERROR:
					switch (pSecu->status.numFb)
					{
					case SECU_SPI:
						switch (pSecu->status.diagCode)
						{
						case mob_def_HM_Inhibition1:
							slog(SLOG_WARNING,"The left three states button is defective");
							SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_BOUTON_TROIS_ETATS_GAUCHE,0,0);
							break;
						case mob_def_HM_Inhibition2:
							slog(SLOG_WARNING,"The right three states button is defective");
							SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_BOUTON_TROIS_ETATS_DROIT,0,0);
							break;
						case mob_def_PdtSurSupport:
							slog(SLOG_WARNING,"The \"HM1 on pendant holder\" sensor is defective");
							SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_DEFAUT_CAPTEUR_PENDANT_SUR_SUPPORT,0,0);
							break;
						case mob_def_spi:
							slog(SLOG_WARNING,"The SPI communication is defective");
							//									SrvDonnee_SetDefaut(&pSecu->connectServDonnees,,0,0);
							break;
						case mob_def_AU:
							slog(SLOG_WARNING,"The ES states button is defective");
							//									SrvDonnee_SetDefaut(&pSecu->connectServDonnees,,0,0);
							break;
						default:
							slog(SLOG_WARNING,"The default (%d) is unknown !", pSecu->status.diagCode);
							//									SrvDonnee_SetDefaut(&pSecu->connectServDonnees,,0,0);
							break;
						}
						break;
						case GEST_WDOG_IHM:
							slog(SLOG_WARNING,"The IHM did not produce heartbeat");
							SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_IHM_HEART_BEAT_START,0,0);
							break;
						default:
							break;
					}
					break;
					/*----------------------------------------------*/
					/* erreur generee par les fonctions de secu CPU */
					/*----------------------------------------------*/
					case SECU_CPU_ERROR:
						switch (pSecu->status.numFb)
						{
						case GEST_MODE:
							switch (pSecu->status.diagCode)
							{
							case 0xC001:
								slog(SLOG_WARNING,"too many modes");
								SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_DEMANDE_DE_MODE_NON_CONFORME,0,0);
								break;
							case 0xC002:
								slog(SLOG_WARNING,"EXEC module is always in execution...");
								SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_ATTENTE_FIN_EXEC,0,0);
								break;
							case 0xC003:
								slog(SLOG_WARNING,"MANUEL module is always in execution...");
								SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_ATTENTE_FIN_MANUEL,0,0);
								break;
							case 0xC004:
							case 0xC006:
								if (pSecu->protectOkInt == FALSE){
									break;
								}
								slog(SLOG_WARNING,"HMI is not on pendant holder");
								if (getParam(secuAdm.bdp, G_CFGIO, F_GESTION_GACHE1, I_GACHE_FCT) != GACHE_SANS ||
										getParam(secuAdm.bdp, G_CFGIO, F_GESTION_GACHE2, I_GACHE_FCT) != GACHE_SANS	){
									SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_IHM_HORS_SUPPORT_INTERVERROUILLAGE,0,0);
								}
								else {
									SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_IHM_HORS_SUPPORT,0,0);
								}
								/* Raz de la demande de modes */
								SrvDonnee_ecrit(&pSecu->connectServDonnees, wrdSysteme, DEM_CHG_MODES_LOCAL, 0, MASK_DEM_MODE_LOCAL, 0);
								break;
							case 0xC005:
								slog(SLOG_WARNING,"AUTO or INIT_AUTO forbidden");
								SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_MODE_PAS_AUTORISE,0,0);
								/* Raz de la demande de modes */
								SrvDonnee_ecrit(&pSecu->connectServDonnees, wrdSysteme, DEM_CHG_MODES_LOCAL, 0, MASK_DEM_MODE_LOCAL, 0);
								break;
							case 0xC007:
							case 0xC008:
							case 0xC009:
							case 0xC00A:
							case 0xC00B:
							case 0xC00C:
								slog(SLOG_WARNING,"Bad reset signal");
								SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_ACQUITTEMENT_NON_CONFORME,0,0);
								break;
							default:
								break;
							}
							break;
							case GEST_COM_EXT:
								switch (pSecu->status.diagCode)
								{
								case 0xC001:
								case 0xC006:
								case 0xC007:
								case 0xC008:
									slog(SLOG_WARNING,"Invalid external command (DiagCode = 0x%X)", pSecu->status.diagCode);
									SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_CDE_EXT_NON_VALIDE,0,0);
									break;
								case 0xC002:
								case 0xC003:
								case 0xC004:
								case 0xC005:
									slog(SLOG_WARNING,"Too many external commandes (DiagCode = 0x%X)", pSecu->status.diagCode);
									SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_DEMANDE_DE_CDE_EXT_NON_CONFORME,0,0);
									break;
								default:
									break;
								}
								break;
								case GEST_START:
									switch (pSecu->status.diagCode)
									{
									case 0xC001:
										slog(SLOG_WARNING,"Start and stop requests (DiagCode = %d)", pSecu->status.diagCode);
										SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_DEMANDE_DE_START_STOP_NON_CONFORME,0,0);
										break;
									default:
										break;
									}
									break;
									case GEST_INHIBPROTECT:
										switch (pSecu->status.diagCode)
										{
										case 0xC001:
											slog(SLOG_WARNING,"INHIB_PROTECT mode forbidden");
											SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_INHIB_PROTECT_PAS_AUTORISE,0,0);
											break;
										case 0xC002:
											slog(SLOG_WARNING,"At least one of the three states buttons is pushed");
											SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_DEFAUT_BOUTON_TROIS_ETATS_CAS_2,0,0);
											break;
										case 0xC003:
											slog(SLOG_WARNING,"A change of three states button was detected");
											SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_CHANGEMENT_DE_BOUTON_TROIS_ETATS_DETECTE,0,0);
											popup = TRUE;
											break;
										case 0xC004:
										case 0xC005:
											slog(SLOG_WARNING,"Bad reset signal");
											SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_ACQUITTEMENT_NON_CONFORME,0,0);
											break;
										default:
											break;
										}
										break;
										case GEST_NODE:
											slog(SLOG_WARNING,"Warning: the following nodes are uncontrolled (W446=0x%08X, W447=0x%08X)", inSecu.nodesUncontrolled[0], inSecu.nodesUncontrolled[1]);
											SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_NOEUD_NON_CONTROLES,0,0);
											break;
										case GEST_24S:
											slog(SLOG_WARNING,"24S signal is always enabled");
											SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_24S_TOUJOURS_PRESENT,0,0);
											break;
										case GEST_STO:
											slog(SLOG_WARNING,"STO signal is always enabled");
											SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_SECU_STO_TOUJOURS_PRESENT,0,0);
											break;
										case GEST_STAUBLI:
											slog(SLOG_WARNING,"Staubli power is always enabled");
											SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_ROBOT_STAUBLI_SAFETY,0,0);
											break;
										default:
											break;
						}
						break;
						/*----------------------------*/
						/* erreur generee par staubli */
						/*----------------------------*/
						case SECU_STAUBLI_ERROR:
							switch (pSecu->status.numFb)
							{
							case GEST_COMM:
								slog(SLOG_WARNING,"Staubli communication error");
								SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_ROBOT_STAUBLI_SECU_COMM,0,0);
								break;
							case GEST_WDOG:
								slog(SLOG_WARNING,"Staubli did not produce heartbeat");
								SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_ROBOT_STAUBLI_WATCHDOG,0,0);
								break;
							case GEST_AU_ERROR:
								slog(SLOG_WARNING,"Staubli Emmergency line opened");
								SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_ROBOT_STAUBLI_LIGNE_AU_OUVERTE,0,0);
								break;
							case GEST_HARDWARE_ERROR:
								slog(SLOG_WARNING,"Staubli has a hardware fault");
								SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_ROBOT_STAUBLI_HARDWARE, inStatus.diagCode,0);
								break;
							case GEST_VAGV:
								slog(SLOG_WARNING,"Staubli speed is too high");
								SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_ROBOT_STAUBLI_VAGV, inStatus.diagCode,0);
								break;default:
									break;
							}
							break;
							default:
								break;
			}
			pthread_mutex_lock(&secuAdm.mutexStatus);
			inStatus.aTraiter = FALSE;
			pthread_mutex_unlock(&secuAdm.mutexStatus);
		}
		/*-----------------------------------------*/
		/* s'assure que l'on peut écrire un pop-up */
		/*-----------------------------------------*/
		if (0 == (pSecu->numPopup & MASQUE_NUM_QUESTION) && TRUE == popup) {
			SrvDonnee_ecrit(&pSecu->connectServDonnees, wrdSysteme, QUESTION_CPU2IHM, ASK_CHANGEMENT_BOUTON_HOMME_MORT | QUEST_OK_SEUL, ~0, 0);
			questionPosee = TRUE;
		}
		if (TRUE == questionPosee) {
			switch(pSecu->numPopup) {
			case REPONSE_OUI :
				questionPosee = FALSE;
				pSecu->selectBpValid = TRUE;
				popup = FALSE;
				SrvDonnee_ecrit(&pSecu->connectServDonnees, wrdSysteme, QUESTION_CPU2IHM, 0, ~0, 0);
				break;
			default :
				if (FALSE == pSecu->enInhibProtect) {
					questionPosee = FALSE;
					pSecu->selectBpValid = FALSE;
					popup = FALSE;
					SrvDonnee_ecrit(&pSecu->connectServDonnees, wrdSysteme, QUESTION_CPU2IHM, 0, ~0, 0);
				}
				break;
			}
		} else {
			pSecu->selectBpValid = FALSE;
		}
		pthread_mutex_lock(&secuAdm.mutexSecu);
		/*-------------------------------*/
		/* Reset des variables de defaut */
		/*-------------------------------*/
		if (pSecu->reset && !pSecu->reset_old)
		{
			/* pour chaque bus can */
			for(numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
			{
				inSecu.emerError[numCan] = 0;
			}
			/* reset du status */
			RST_ERROR;
			popup = FALSE;
			questionPosee = FALSE;
			pSecu->selectBpValid = FALSE;
			SrvDonnee_ecrit(&pSecu->connectServDonnees, wrdSysteme, QUESTION_CPU2IHM, 0, ~0, 0);
		}
		pSecu->reset_old = pSecu->reset;

		/*----------------------------------------------------------------------------*/
		/* teste si il-y-a eu un changement de parametre ou de configuration materiel */
		/*----------------------------------------------------------------------------*/
		if ((secuAdm.flagMajFilter) && (simu == FALSE))
		{
			configFiltre(pSecu);
			secuAdm.flagMajFilter = 0;
		}
		pthread_mutex_unlock(&secuAdm.mutexSecu);

		/*----------------------------------------------------------------*/
		/* Rend le semaphore pour autoriser la mise a jour des parametres */
		/*----------------------------------------------------------------*/
		sem_post(&secuAdm.synchroParam);

		delay(SECU_PERIODE);
	}
	return EXIT_SUCCESS;
}

/**
 * \brief Gestion du start et de l'acquittement des defauts
 * \param pointeur sur la strucure locale
 * \param pointeur sur la fonction de securite
 * \return
 */
void gest_start(secuLoc_t *pSecu, FB_GESTSTART *pGestStart)
{
	/*----------------------------------*/
	/* Memorisation protecteurs ouverts */
	/*----------------------------------*/
	if (!pSecu->protectOkInt) pSecu->protectOkInt_mem = 0;

	/*-------------------------------*/
	/* Initialisation de la fonction */
	/*-------------------------------*/
	pGestStart->period              = pSecu->periode;
	pGestStart->in.activate         = pSecu->activate;
	pGestStart->in.defautEnCours    = (bool)(pSecu->status.defaut);
	pGestStart->in.execValide       = (bool)(!(pSecu->demChgModes & LOCAL_PRG_BUSY) && (pSecu->nivModesEnCours & MASK_MODES_EXEC) && pSecu->prgSelectionne);
	pGestStart->in.memProtectOuvert = (bool)(!pSecu->protectOkInt_mem || (!pSecu->ihmSurSupport && (pSecu->nivModesEnCours & EN_AUTO)));
	pGestStart->in.demChgModes      = (bool)(pSecu->demChgModes & MASK_DEM_MODE_LOCAL);
	pGestStart->preStartTime        = secuAdm.preStartTime;
	pGestStart->startTime           = START_TIME;
	pGestStart->acquitTime          = ACQUIT_TIME;
	pGestStart->in.demStop          = (bool)(pSecu->demChgModes & LOCAL_DEM_STOP);
	pGestStart->in.demStart         = (bool)(!pSecu->sansPendant && ((pSecu->demChgModes & LOCAL_DEM_START_MEM) || ((pSecu->demChgModes & LOCAL_DEM_ACQUIT) && pSecu->status.defaut)));

	/*---------------------*/
	/* Appel a la fonction */
	/*---------------------*/
	fb_gestStart(pGestStart);

	/*------------------------------------------*/
	/* Prise en compte des etats ready et error */
	/*------------------------------------------*/
	pSecu->ready &= pGestStart->out.ready;
	if (pGestStart->out.error)
		SET_ERROR(SECU_CPU_ERROR, GEST_START, pGestStart->diagCode);

	/*---------------------------*/
	/* Mise en forme de NIV_MODE */
	/*---------------------------*/
	if (pGestStart->out.enStop)
		pSecu->nivModes |= T_STOP;
	else if (pGestStart->out.preStart)
		pSecu->nivModes |= SECU_BUZZER;
	else if (pGestStart->out.enStart)
	{
		pSecu->nivModes |= T_START;
		pSecu->protectOkInt_mem = pSecu->protectOkInt;
	}
	pSecu->acquitDefaut = pGestStart->out.enAcquit;

	/*--------------------------------------*/
	/* Warning si pas de prg de selectionne */
	/*--------------------------------------*/
	if ((pSecu->prgSelectionne == FALSE) && (pGestStart->out.enStart == TRUE))
		SrvDonnee_SetDefaut(&pSecu->connectServDonnees,D_IHM_PAS_PRG_SELECTIONNE,0,0);

	/*------------------------------------------------------*/
	/* Acquittement des warning si pas de defaut et T_START */
	/*------------------------------------------------------*/
	if ((pGestStart->out.enStart == TRUE) && (pSecu->numDefEnCours != 197) && !pSecu->status.defaut)
	{
		if (pSecu->warnAcquitte == FALSE)
			pSecu->acquitWarning = TRUE;
	}
	if (pGestStart->out.enStart == FALSE)
	{
		pSecu->warnAcquitte  = FALSE;
		pSecu->acquitWarning = FALSE;
	}
}

/**
 * \brief Gestion du type d'arret (categorie 0 ou 1)
 * 		  La demande de mode emise par vnc display est validee ici en fonction
 * 		  du contexte
 * \param pointeur sur la strucure locale
 * \return
 * Evaluation du type d'arret: hors mode auto ou si les axes sont supposes
 * a l'arret, on genere un arret de categorie 0. L'arret interviendra
 * apres un delai de 100ms pour compenser le temps de reaction des freins.
 * En configuration Staubli, l'arret est immediat (la commande gere ses
 * propres arrets).
 */
void gest_arret(secuLoc_t *pSecu)
{
	static int delai = 100;	/* prise en compte d'un temps de reaction des freins */

	if (secuAdm.options.Axes.robot6x != sans6x){
		pSecu->arretCat0 = TRUE;
	}
	else if (pSecu->stopAxes != 0){
		if ((pSecu->nivModesEnCours & EN_AUTO) == 0 || pSecu->axesArretes == TRUE){
			if (delai <= 0){
				if (pSecu->arretCat0 == FALSE){
					slog(SLOG_DEBUG1,"switching category 0 stop");
				}
				pSecu->arretCat0 = TRUE;
			}
			else {
				delai -= pSecu->periode;
			}
		}
	}
	else {
		/* initialisation des conditions */
		pSecu->arretCat0 = FALSE;
		delai = 100;
		pthread_mutex_lock(&secuAdm.mutexSecu);
		inSecu.axesArretes = FALSE;
		pthread_mutex_unlock(&secuAdm.mutexSecu);
	}
}

/**
 * \brief Gestion des modes de marche
 * \param pointeur sur la strucure locale
 * \param pointeur sur la fonction de securite
 * \return
 */
void gest_modes(secuLoc_t *pSecu, FB_GESTMODE *pGestMode )
{
	/*-------------------------------*/
	/* Initialisation de la fonction */
	/*-------------------------------*/
	pGestMode->period             = pSecu->periode;
	pGestMode->in.activate        = pSecu->activate;
	pGestMode->in.reset           = pSecu->reset;
	pGestMode->in.execEnCours     = pSecu->execEnCours;
	pGestMode->in.manuEnCours     = pSecu->manuEnCours;
	pGestMode->in.defautEnCours   = (bool)pSecu->status.defaut;
	pGestMode->in.enInhibProtect  = pSecu->enInhibProtect;
	pGestMode->in.ihmHorsProtect  = pSecu->ihmHorsProtect;
	pGestMode->in.demManuel       = (bool)(pSecu->demChgModes & LOCAL_DEM_MANUEL);
	pGestMode->in.demEssaiContinu = (bool)(pSecu->demChgModes & LOCAL_DEM_ESSAI_CONTINU);
	pGestMode->in.demEssaiPasAPas = (bool)(pSecu->demChgModes & LOCAL_DEM_ESSAI_PASAPAS);
	pGestMode->in.demAuto         = (bool)(pSecu->demChgModes & LOCAL_DEM_AUTO);
	pGestMode->threadTimeOut      = TIMEOUT_EXEC_MANU;

	/*---------------------*/
	/* Appel a la fonction */
	/*---------------------*/
	fb_gestMode(pGestMode);

	/*------------------------------------------*/
	/* Prise en compte des etats ready et error */
	/*------------------------------------------*/
	pSecu->ready &= pGestMode->out.ready;
	if (pGestMode->out.error)
		SET_ERROR(SECU_CPU_ERROR, GEST_MODE, pGestMode->diagCode);

	/*---------------------------*/
	/* Mise en forme de NIV_MODE */
	/*---------------------------*/
	if      (pGestMode->out.enManuel)
		pSecu->nivModes |= EN_MANUEL_USER;
	else if (pGestMode->out.enEssaiContinu)
		pSecu->nivModes |= EN_ESSAI_CONTINU;
	else if (pGestMode->out.enEssaiPasAPas)
		pSecu->nivModes |= EN_ESSAI_PASAPAS;
	else if (pGestMode->out.enAuto)
		pSecu->nivModes |= EN_AUTO;

	/*-------------------------------------------------------------------*/
	/* La puissance doit retomber lors d'un changement de mode lorsque   */
	/* les protecteurs sont inhibes.                                     */
	/* Mise en conformite avec ISO 10218-1 aout 2011 chapitre 5.8.3.h)   */
	/*-------------------------------------------------------------------*/
	/* Ce cas est supprime, car au sens de la norme, nos modes Manuel et */
	/* Essai(s) font partie du même mode "Mode manuel en vitesse réduite"*/
	/*-------------------------------------------------------------------*/
	/*
	if (pGestMode->diagCode == 0x8002 && pSecu->protectInhibe == TRUE)
		SET_ERROR(SECU_CPU_ERROR, GEST_MODE, 0);
	 */
}

/**
 * \brief Gestion du mode inhibition des protecteurs
 * \param pointeur sur la strucure locale
 * \param pointeur sur la fonction de securite
 * \return
 */
void gest_inhibProtect(secuLoc_t *pSecu, FB_INHIBPROTECT *pInhibProtect)
{
	/*-------------------------------*/
	/* Initialisation de la fonction */
	/*-------------------------------*/
	pInhibProtect->period             = pSecu->periode;
	pInhibProtect->in.activate        = pSecu->activate;
	pInhibProtect->in.reset           = pSecu->reset;
	pInhibProtect->in.bpValidG        = pSecu->bpValidG;
	pInhibProtect->in.bpValidD        = pSecu->bpValidD;
	pInhibProtect->in.ihmSurSupport   = pSecu->ihmSurSupport;
	pInhibProtect->in.demInhibProtect = pSecu->demInhibProtect;
	pInhibProtect->in.modeValide      = (bool)((pSecu->nivModesEnCours & MODES_INHIBPROTECT_VALIDES) || !(pSecu->nivModesEnCours & MASQ_MODES));
	pInhibProtect->in.selectBpValid   = pSecu->selectBpValid;
	pInhibProtect->monitoringTime     = 200;

	/*---------------------*/
	/* Appel a la fonction */
	/*---------------------*/
	fb_inhibProtect(pInhibProtect);

	/*------------------------------------------*/
	/* Prise en compte des etats ready et error */
	/*------------------------------------------*/
	pSecu->ready &= pInhibProtect->out.ready;
	if (pInhibProtect->out.error)
		SET_ERROR(SECU_CPU_ERROR, GEST_INHIBPROTECT, pInhibProtect->diagCode);

	/*---------------------------*/
	/* Mise en forme de NIV_MODE */
	/*---------------------------*/
	if (pInhibProtect->out.enInhibProtect)
		pSecu->nivModes |= EN_INHIB_PROTECT;

	pSecu->enInhibProtect = pInhibProtect->out.enInhibProtect;
	pSecu->protectInhibe  = pInhibProtect->out.protectInhibe;
}

/**
 * \brief Gestion du pendant deconnectable
 * \param pointeur sur la strucure locale
 * \return
 */
void gest_sansPendant(secuLoc_t *pSecu)
{
	if(!pSecu->sansPendant && pSecu->sansPendant_old)
	{
		/* Reset le wdog IHM */
		pSecu->wDogIhmCount = 0;

		/* Relance la communication SPI apres une deconnexion du pendant */
		if (pSecu->threadSpiStopped)
			sem_post (&secuAdm.semThreadSpi);
	}
	pSecu->sansPendant_old = pSecu->sansPendant;
}

/**
 * \brief Surveillance des WDog interface et IHM
 * \param pointeur sur la strucure locale
 * \return
 */
void gest_wDog(secuLoc_t *pSecu)
{
	int wDogIhmPeriode;

	/*---------------------*/
	/* Gestion du WDog IHM */
	/*---------------------*/
	if (pSecu->sansPendant)
		wDogIhmPeriode = secuAdm.wdogIhmOffPeriode;
	else
		wDogIhmPeriode = WDOG_IHM_ON_PERIODE;

	if ((pSecu->demChgModes & LOCAL_DEM_REARM_WDOG) && !pSecu->sansPendant)
		pSecu->wDogIhmCount = 0;

	if (pSecu->wDogIhmCount >= wDogIhmPeriode)
		SET_ERROR(SECU_IHM_ERROR, GEST_WDOG_IHM, 0);
	else
		pSecu->wDogIhmCount += pSecu->periode;

	/*---------------------------*/
	/* Gestion du WDog interface */
	/*---------------------------*/
	if (pSecu->wDogIntCount >= WDOG_INT_PERIODE)
		pSecu->wDogIntCount = pSecu->periode;
	else
		pSecu->wDogIntCount += pSecu->periode;
}

/**
 * \brief Controle que le 24S retombe bien lors d'un defaut de securite
 * \param pointeur sur la strucure locale
 * \return
 */
void gest_ctrl24S(secuLoc_t *pSecu)
{
	static int mask_def = 0;
	static int cmpt = 0;

	if (!pSecu->validAxeInt && pSecu->powerOkInt && cmpt < MONITORING_TIME_24S){
		cmpt += pSecu->periode;
	}
	else if (!pSecu->validAxeInt && !pSecu->powerOkInt){
		cmpt = 0;
		mask_def = 0;
	}
	if (cmpt > MONITORING_TIME_24S){
		if (mask_def == 0){
			SET_ERROR(SECU_CPU_ERROR, GEST_24S, 0);
		}
		mask_def = 1;
	}
	if (pSecu->reset && !pSecu->reset_old){
		mask_def = 0;
	}
}

/**
 * \brief controle que les entrees STO retombent bien sur un arret de securite
 *        L'etat des entrees est demande par un SDO2 apres la perte du 24S. Si
 *        l'alimentation puissance du variateur est coupee, les entrees STO
 *        sont ignorees.
 * \param pointeur sur la strucure locale
 * \return
 */
void gest_ctrlSto(secuLoc_t *pSecu)
{
	static int mask_def = 0;
	static int cmptSto = 0;
	static int demfaite = 0;

	if (!pSecu->powerOkInt && cmptSto < MONITORING_TIME_STO){
		if (cmptSto > MONITORING_TIME_STO/2 && demfaite == 0){
			pSecu->demEtatSto[0] |= pSecu->objetStoValide[0];
			pSecu->demEtatSto[1] |= pSecu->objetStoValide[1];
			demfaite = 1;
		}
		cmptSto += pSecu->periode;
	}
	else if (pSecu->powerOkInt){
		if (cmptSto != 0){
			/* forcage des entrees STO */
			pthread_mutex_lock(&secuAdm.mutexSecu);
			inSecu.stoInput[0] = pSecu->objetStoValide[0];
			inSecu.stoInput[1] = pSecu->objetStoValide[1];
			pthread_mutex_unlock(&secuAdm.mutexSecu);
			slog(SLOG_DEBUG1,"Reset des entrees STO: stoInput[0] = 0x%08X, stoInput[1] = 0x%08X", inSecu.stoInput[0], inSecu.stoInput[1]);
		}
		cmptSto = 0;
		demfaite = 0;
		mask_def = 0;
	}
	else if (cmptSto >= MONITORING_TIME_STO && ((pSecu->stoInput[0] & pSecu->puissanceOn[0]) != 0 || (pSecu->stoInput[1] & pSecu->puissanceOn[1]) != 0)){
		if (mask_def == 0){
			slog(SLOG_DEBUG1,"Defaut STO: stoInput[0] = 0x%08X, stoInput[1] = 0x%08X", inSecu.stoInput[0], inSecu.stoInput[1]);
			SET_ERROR(SECU_CPU_ERROR, GEST_STO, 0);
		}
		mask_def = 1;
	}
	if (pSecu->reset && !pSecu->reset_old){
		pSecu->demEtatSto[0] |= pSecu->objetStoValide[0];
		pSecu->demEtatSto[1] |= pSecu->objetStoValide[1];
		mask_def = 0;
	}
}

/**
 * \brief controle que le Staubli a bien pris en compte le defaut de securite
 * \param pointeur sur la strucure locale
 * \return
 */
void gest_ctrlStaubli(secuLoc_t *pSecu)
{
	static int mask_def = 0;
	static int cmpt = 0;

	if (!pSecu->validAxeInt && pSecu->powerOkStaubli && cmpt < MONITORING_TIME_STAUBLI){
		cmpt += pSecu->periode;
	}
	else if (!pSecu->validAxeInt && !pSecu->powerOkStaubli){
		cmpt = 0;
		mask_def = 0;
	}
	if (cmpt > MONITORING_TIME_STAUBLI){
		if (mask_def == 0){
			SET_ERROR(SECU_CPU_ERROR, GEST_STAUBLI, 0);
		}
		mask_def = 1;
	}
	if (pSecu->reset && !pSecu->reset_old){
		mask_def = 0;
	}
}

/**
 * \brief controle l'arret des axes
 * \param pointeur sur la strucure locale
 * \param timeout du msgSend
 * \return
 */
int gest_ctrlAxes(secuLoc_t *pSecu, int timeout)
{
	int result = 0;
	int i;
	recInputBuf_t msgAxe;
	axis_info_msg_t repMsgAxe[NB_AXE_MAX + NB_MAXI_ENTREES];

	/*-----------------------------------------------*/
	/* Determine les axes devant etre arretes ou pas */
	/*-----------------------------------------------*/
	if(!pSecu->validAxeInt || (pSecu->status.defaut && pSecu->status.type == DEFAUT_SECU))
	{
		pSecu->stopAxes = 0xFFFFFFFF;
	}
	else if(pSecu->status.defaut && secuAdm.axePresent != 0)
	{
		/*------------------------------------------------*/
		/* Recherche les axes libres ou les axes suiveurs */
		/*------------------------------------------------*/
		msgAxe.TypeCmd = CMD_INFO_AXES;
		msgAxe.inputData.Commande = 0xFFFFFFFF;
		pSecu->axesLibres = 0x0000000;

		result = MsgSendPlus(pSecu->coidModuleAxe, &msgAxe, sizeof(msgAxe), repMsgAxe, sizeof(repMsgAxe), timeout);

		if (result == -ETIMEDOUT)
		{
			slog(SLOG_ERROR,"Axes module communication error (%s)", strerror(-result));
			SET_ERROR(AXE_ERROR, 0, 0);
		}
		else if (result < 0)
		{
			slog(SLOG_CRITICAL,"Axes module communication error (%s)", strerror(-result));
			SET_ERROR(QNX_ERROR, 0, 0);
		}
		else
		{
			for (i=0; repMsgAxe[i].AxisNo != -1 && i < (NB_AXE_MAX); i++)
			{
				if ((repMsgAxe[i].Status.Axlib || repMsgAxe[i].Status.Axe_Suiveur) && repMsgAxe[i].Output.Defaut == 0)
				{
					pSecu->axesLibres |= 1 << repMsgAxe[i].AxisNo;
				}
			}
		}
		pSecu->stopAxes = ~pSecu->axesLibres;
	}
	else
	{
		pSecu->stopAxes = 0x00000000;
	}
	return (result);
}

/**
 * \brief controle le temps d'execution des threads
 * \param pointeur sur la strucure locale
 * \return
 */
int gest_thread(secuLoc_t *pSecu)
{
	int result = 0;
	unsigned long delta;
	static unsigned long delta_max = 0;
	static unsigned long delta_max_max = 0;
	static int spi_error = 0;
	static int spi_warning = 0;

	/* Execution du thread principale */
	pSecu->periode = (unsigned long)(calculIntervalTps(&pSecu->timeThread, NULL));
	if (pSecu->periode > (2 * SECU_PERIODE))
		slog(SLOG_DEBUG1,"Scheduling warning. periodicity is %d/%dms", pSecu->periode, SECU_PERIODE);

	/* Execution du thread spi */
	if (!pSecu->sansPendant)
	{
		delta = (unsigned long)(calculIntervalTps(&pSecu->timeSpi, NULL));
		if (delta > delta_max)
			delta_max = delta;
		if (delta_max > delta_max_max)
			delta_max_max = delta_max;

		if (delta > TIMEOUT_DRIVER_SPI_ERROR && !spi_error)
		{
			slog(SLOG_CRITICAL,"SPI scheduling error. period > %dms", TIMEOUT_DRIVER_SPI_ERROR);
			SET_ERROR(SPI_ERROR, 0, 0);
			spi_error = 1;
			spi_warning = 1;
		}
		else if (delta > TIMEOUT_DRIVER_SPI_WARNING && !spi_warning)
		{
			slog(SLOG_ERROR,"SPI scheduling warning. period > %dms", TIMEOUT_DRIVER_SPI_WARNING);
			spi_warning = 1;
		}
		else if (delta <= TIMEOUT_DRIVER_SPI_WARNING && spi_error)
		{
			slog(SLOG_WARNING,"SPI scheduling ok. period < %dms (max = %dms, MAX = %dms)", TIMEOUT_DRIVER_SPI_WARNING, delta_max, delta_max_max);
			spi_error = 0;
			spi_warning = 0;
			delta_max = 0;
		}
		else if (delta <= TIMEOUT_DRIVER_SPI_WARNING && spi_warning)
		{
			slog(SLOG_DEBUG1,"SPI scheduling ok. period < %dms (max = %dms, MAX = %dms)", TIMEOUT_DRIVER_SPI_WARNING, delta_max, delta_max_max);
			spi_warning = 0;
			delta_max = 0;
		}
	}
	/* Execution du thread staubli */
	if (secuAdm.options.Axes.robot6x != sans6x)
	{
		delta = (unsigned long)(calculIntervalTps(&pSecu->timeStaubli, NULL));
		if (delta > (5*TIMEOUT_STAUBLI))
		{
			slog(SLOG_CRITICAL,"Staubli scheduling error. periodicity is %d/%dms", delta, 5*TIMEOUT_STAUBLI);
			SET_ERROR(STAUBLI_ERROR, 0, 0);
		}
		else if (delta > TIMEOUT_STAUBLI)
		{
			slog(SLOG_DEBUG1,"Staubli scheduling warning. periodicity is %d/%dms", delta, TIMEOUT_STAUBLI);
		}
	}
	return result;
}

/**
 * \brief Gestion du mode d'affichage et de commande, local ou OEM(deporte)
 * 		  La demande de mode emise par vnc display est validee ici en fonction
 * 		  du contexte
 * \param pointeur sur la strucure locale
 * \param pointeur sur la fonction de securite
 * \return
 */
void gest_cdeDeportee(secuLoc_t *pSecu, FB_GESTVNC *pGestVnc)
{
	/*-------------------------------*/
	/* Initialisation de la fonction */
	/*-------------------------------*/
	pGestVnc->in.activate = pSecu->activate;
	pGestVnc->in.startModeLocal = TRUE;
	pGestVnc->in.enInhibitprotect = pSecu->enInhibProtect;
	pGestVnc->in.pendantSurSupport = pSecu->ihmSurSupport;
	pGestVnc->in.demModeLocal = (bool)(pSecu->demModeVnc == secu_vnc_dem_local);
	pGestVnc->in.demModeOem = (bool)(pSecu->demModeVnc == secu_vnc_dem_oem);

	/*---------------------*/
	/* Appel a la fonction */
	/*---------------------*/
	fb_gestVnc(pGestVnc);

	/*------------------------------------------*/
	/* Prise en compte des etats ready et error */
	/*------------------------------------------*/
	pSecu->ready &= pGestVnc->out.ready;

	/*-----------------------------------*/
	/* Mise en forme du mode d'affichage */
	/*-----------------------------------*/
	if (pGestVnc->out.enModeLocalSecu == TRUE){
		pSecu->modeVnc = display_mode_local_verrou;
	}
	else if (pGestVnc->out.enModeLocal == TRUE){
		pSecu->modeVnc = display_mode_local;
		pSecu->nivModes |= EXT_ACTIF;
	}
	else if (pGestVnc->out.enModeOem == TRUE){
		pSecu->modeVnc = display_mode_oem;
		pSecu->nivModes |= EXT_ACTIF;
	}
	else {
		pSecu->modeVnc = -1;
	}
	/*------------------------------------*/
	/* Mise en forme des demandes de mode */
	/*------------------------------------*/

	/* prise en compte des autres demandes en fonction du contexte */
	if (pSecu->modeVnc != display_mode_local_verrou){
		/* les demandes de mode externes sont ignorees si une demande locale est en cours */
		if ((pSecu->demChgModes & MASK_DEM_MODE_LOCAL) == 0){
			if (pSecu->demChgModesExt & EXT_DEM_MANUEL_PV)
				pSecu->demChgModes |= LOCAL_DEM_MANUEL;

			if (pSecu->demChgModesExt & EXT_DEM_ESSAI_CONTINU)
				pSecu->demChgModes |= LOCAL_DEM_ESSAI_CONTINU;

			if (pSecu->demChgModesExt & EXT_DEM_ESSAI_PASAPAS)
				pSecu->demChgModes |= LOCAL_DEM_ESSAI_PASAPAS;

			if (pSecu->demChgModesExt & EXT_DEM_AUTO)
				pSecu->demChgModes |= LOCAL_DEM_AUTO;
		}
		/* les demandes de start externes sont ignorees si une demande locale est en cours */
		if ((pSecu->demChgModes & LOCAL_DEM_STOP) == 0){
			if (pSecu->demChgModesExt & EXT_DEM_START_MEM)
				pSecu->demChgModes |= LOCAL_DEM_START_MEM;

			if (pSecu->demChgModesExt & EXT_DEM_START_KEY)
				pSecu->demChgModes |= LOCAL_DEM_START_KEY;
		}
		if (pSecu->demChgModesExt & EXT_DEM_ACQUIT)
			pSecu->demChgModes |= LOCAL_DEM_ACQUIT;

		if (pSecu->demChgModesExt & EXT_DEM_POWER_OFF)
			pSecu->demChgModes |= LOCAL_DEM_POWER_OFF;

		if (pSecu->demChgModesExt & EXT_DEM_POWER_ON)
			pSecu->demChgModes |= LOCAL_DEM_POWER_ON;
	}
	/* la demande de stop externe est toujours prise en compte */
	if (pSecu->demChgModesExt & EXT_DEM_STOP)
		pSecu->demChgModes |= LOCAL_DEM_STOP;
}

/**
 * \brief Determine la position du pendant par rapport a la zone dangereuse.
 *        Le pendant est considere hors zone dangereuse:
 *        - tant qu'il est sur son support,
 *        - il n'est plus sur son support mais les protecteurs n'ont pas ete ouverts depuis
 *        - l'option interverrouillage est presente et les protecteurs sont fermes et verrouilles
 * \param pointeur sur la strucure locale
 * \param pointeur sur la fonction de securite
 * \return
 */
void gest_posPendant(secuLoc_t *pSecu, FB_GESTINTERVERROU *pGestInterverrou)
{
	/* determine si les protecteurs sont presents et non shuntes */
	/* prise en compte lors de l'ouverture */
	if (pSecu->protectOkInt == 0 && (pSecu->protectOkInt_old == 1 || pSecu->demVerrouGache1 == 1 || pSecu->demVerrouGache2 == 1)){
		pSecu->protectPresent = 1;
	}
	pSecu->protectOkInt_old = pSecu->protectOkInt;

	/*-------------------------------*/
	/* Initialisation de la fonction */
	/*-------------------------------*/
	pGestInterverrou->period = pSecu->periode;
	pGestInterverrou->in.activate = pSecu->activate;
	pGestInterverrou->in.demVerrou_1 = pSecu->demVerrouGache1;
	pGestInterverrou->in.demVerrou_2 = pSecu->demVerrouGache2;
	pGestInterverrou->in.pendantSurSupport = pSecu->ihmSurSupport;
	pGestInterverrou->in.protectVerrou = (bool)(pSecu->protectPresent == TRUE && pSecu->protectOkInt == TRUE);
	pGestInterverrou->timeout = 2000;

	/*---------------------*/
	/* Appel a la fonction */
	/*---------------------*/
	fb_gestInterverrou(pGestInterverrou);

	/*------------------------------------------*/
	/* Prise en compte des etats ready et error */
	/*------------------------------------------*/
	pSecu->ready &= pGestInterverrou->out.ready;

	/*-----------------------------------*/
	/* Mise en forme du mode d'affichage */
	/*-----------------------------------*/
	pSecu->ihmHorsProtect = pGestInterverrou->out.pendantHorsZone;
}

/*=====================================================================
  Function Name  : comm_servDonnee
  Description    : communication avec le serveur de donnee
  Parameter      : pointeur sur la strucure locale
  Parameter      : timeout du msgSend
  Return         : ok ou erreur
======================================================================*/
int comm_servDonnee(secuLoc_t *pSecu, int timeout)
{
	int result = 0;
	ecritGrp_t demEcrit;
	unsigned long demModes;
	statusSrvDonnee_t statusSrvDonnee;
	int numCan;
	int numNode;
	int numAxe;

	initSrvEcritGrp(&demEcrit);

	/*--------------------------*/
	/* Acquittement des warning */
	/*--------------------------*/
	if (pSecu->acquitWarning == TRUE)
	{
		statusSrvDonnee = SrvDonnee_AquitDefaut(&pSecu->connectServDonnees, timeout);
		pSecu->warnAcquitte  = TRUE;
		pSecu->acquitWarning = FALSE;
	}
	/*----------------------------------------------*/
	/* si secu a genere un acquittement des defauts */
	/*----------------------------------------------*/
	if(pSecu->reset)
	{
		slog(SLOG_INFO,"Secu received a reset signal");
		statusSrvDonnee = SrvDonnee_AquitDefaut(&pSecu->connectServDonnees, timeout);
		pSecu->modeALancer = 0;
		if (statusSrvDonnee.status != pasErreur)
		{
			slog(SLOG_CRITICAL,"System error. Impossible to write in the Data Server. srvStatus is %d", (int)statusSrvDonnee.status);
			SET_ERROR(SERVDON_ERROR, 0, 0);
		}
		else
		{
			/*-------------------------*/
			/* restitution du contexte */
			/*-------------------------*/
			if(!(pSecu->demChgModesLoc & MASK_DEM_MODE_LOCAL))
			{
				demModes = 0;
				if      (pSecu->nivModesEnCours & EN_MANUEL_USER)
					demModes = LOCAL_DEM_MANUEL;
				else if (pSecu->nivModesEnCours & EN_AUTO)
					demModes = LOCAL_DEM_AUTO;
				else if (pSecu->nivModesEnCours & EN_ESSAI_PASAPAS)
					demModes = LOCAL_DEM_ESSAI_PASAPAS;
				else if (pSecu->nivModesEnCours & EN_ESSAI_CONTINU)
					demModes = LOCAL_DEM_ESSAI_CONTINU;

				SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_LOCAL, demModes, MASK_DEM_MODE_LOCAL);
			}
		}
	}
	/*---------------------------------------------------------------*/
	/* Acquittement des defauts lors de l'inhibition des protecteurs */
	/*---------------------------------------------------------------*/
	/* En mode Inhibition des protecteurs, et en l'absence de defaut "grave", l'appui sur un des */
	/* boutons trois etats genere un reset pour rearmer les fonctions de secu de l'interface     */
	if (pSecu->protectInhibe && !pSecu->protectInhibe_old)
	{
		statusSrvDonnee = SrvDonnee_ecrit(&pSecu->connectServDonnees, wrdSysteme, DEM_CHG_MODES_LOCAL, LOCAL_DEM_START_MEM, LOCAL_DEM_START_MEM, 0);
	}
	pSecu->protectInhibe_old = pSecu->protectInhibe;

	/*------------------------------------------------------*/
	/* Acquittement des defauts lors du forcage des limites */
	/*------------------------------------------------------*/
	if (pSecu->forceDeplacement && !pSecu->forceDeplacement_old)
	{
		statusSrvDonnee = SrvDonnee_ecrit(&pSecu->connectServDonnees, wrdSysteme, DEM_CHG_MODES_LOCAL, LOCAL_DEM_START_MEM, LOCAL_DEM_START_MEM, 0);
	}
	pSecu->forceDeplacement_old = pSecu->forceDeplacement;

	/*----------------------------------------------*/
	/* si secu a valide un nouveau mode d'execution */
	/*----------------------------------------------*/
	if (((pSecu->nivModes & MASK_MODES_EXEC_MANU) != (pSecu->nivModes_old & MASK_MODES_EXEC_MANU)) && (pSecu->nivModes & MASK_MODES_EXEC_MANU))
	{
		slog(SLOG_INFO,"New nivModes=0x%08x (0x%08x)", pSecu->nivModes, pSecu->nivModes_old);
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, pSecu->nivModes, MASK_MODES_EXEC_MANU | EN_INHIB_PROTECT);
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_LOCAL, 0, MASK_DEM_MODE_LOCAL);
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_EXT, 0, MASK_DEM_MODE_EXT);
	}
	/*---------------------------------------------------------------*/
	/* si secu a valide un nouveau mode d'inhibition des protecteurs */
	/*---------------------------------------------------------------*/
	else if (((pSecu->nivModes & EN_INHIB_PROTECT) != (pSecu->nivModes_old & EN_INHIB_PROTECT)))
	{
		slog(SLOG_INFO,"nivModes=0x%08x (0x%08x)", pSecu->nivModes, pSecu->nivModes_old);
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, pSecu->nivModes, EN_INHIB_PROTECT);
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_LOCAL, 0, LOCAL_DEM_INHIB_PROTECT);
	}
	/*----------------------------------------*/
	/* si secu a valide une nouvelle commande */
	/*----------------------------------------*/
	if ((pSecu->nivModes & MASK_NEW_CDE) != (pSecu->nivModes_old & MASK_NEW_CDE))
	{
		slog(SLOG_INFO,"New nivModes=0x%08x (0x%08x)", pSecu->nivModes, pSecu->nivModes_old);
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, pSecu->nivModes, MASK_NEW_CDE);
	}
	/*-------------------------------------------------------------------------*/
	/* memorisation de la demande de stop (utilisee pour la gestion du buzzer) */
	/*-------------------------------------------------------------------------*/
	if (pSecu->demChgModes & LOCAL_DEM_STOP)
	{
		//slog(SLOG_INFO,"Secu validated a new state nivModes=0x%08x (0x%08x)", pSecu->nivModes, pSecu->nivModes_old);
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, MEM_DEM_STOP, MEM_DEM_STOP);
	}
	else if (pSecu->demChgModes & LOCAL_DEM_START_MEM)
	{
		//slog(SLOG_INFO,"Secu validated a new state nivModes=0x%08x (0x%08x)", pSecu->nivModes, pSecu->nivModes_old);
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, ~MEM_DEM_STOP, MEM_DEM_STOP);
	}
	/*--------------------------------------------*/
	/* si secu a recu un rearmement du wdog l'IHM */
	/*--------------------------------------------*/
	if (pSecu->demChgModes & LOCAL_DEM_REARM_WDOG)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_LOCAL, 0, LOCAL_DEM_REARM_WDOG);

	/*----------------------------*/
	/* Reset les demandes de Stop */
	/*----------------------------*/
	if (pSecu->demChgModesLoc & LOCAL_DEM_STOP)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_LOCAL, ~LOCAL_DEM_STOP, LOCAL_DEM_STOP);
	if (pSecu->demChgModesExt & EXT_DEM_STOP)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_EXT, ~EXT_DEM_STOP, EXT_DEM_STOP);

	/*-------------------------*/
	/* Raz des autres demandes */
	/*-------------------------*/
	if ((pSecu->demChgModesLoc & LOCAL_DEM_START_MEM) && !(pSecu->demChgModesLoc & LOCAL_DEM_START_KEY))
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_LOCAL, ~LOCAL_DEM_START_MEM, LOCAL_DEM_START_MEM);
	if ((pSecu->demChgModesExt & EXT_DEM_START_MEM) && !(pSecu->demChgModesExt & EXT_DEM_START_KEY))
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_EXT, ~EXT_DEM_START_MEM, EXT_DEM_START_MEM);

	if (pSecu->demChgModesLoc & LOCAL_DEM_ACQUIT)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_LOCAL, 0, LOCAL_DEM_ACQUIT);
	if (pSecu->demChgModesExt & EXT_DEM_ACQUIT)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_EXT, 0, EXT_DEM_ACQUIT);

	if (pSecu->demChgModesLoc & LOCAL_DEM_POWER_OFF)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_LOCAL, 0, LOCAL_DEM_POWER_OFF);
	if (pSecu->demChgModesExt & EXT_DEM_POWER_OFF)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_EXT, 0, EXT_DEM_POWER_OFF);

	if (pSecu->demChgModesLoc & LOCAL_DEM_POWER_ON)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_LOCAL, 0, LOCAL_DEM_POWER_ON);
	if (pSecu->demChgModesExt & EXT_DEM_POWER_ON)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_CHG_MODES_EXT, 0, EXT_DEM_POWER_ON);

	/*----------------------------------------------------------------------------*/
	/* Mise a jour des variables de sortie SECU_OK, POWER_OK et PENDANT_HORS_ZONE */
	/*----------------------------------------------------------------------------*/
	if (!pSecu->status.defaut && pSecu->powerOkInt && pSecu->validAxeInt)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, SECU_OK, SECU_OK);
	else
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, 0, SECU_OK);

	if (pSecu->powerOkInt == TRUE)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, WORD_SECURITE, POWER_OK, POWER_OK);
	else
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, WORD_SECURITE, 0, POWER_OK);

	if (pSecu->ihmHorsProtect == TRUE)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, PENDANT_HORS_ZONE, PENDANT_HORS_ZONE);
	else
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, 0, PENDANT_HORS_ZONE);

	/*---------------------------------------------------------*/
	/* Si une demande d'initialisation des axes est necessaire */
	/*---------------------------------------------------------*/
	if (pSecu->status.defaut)
	{
		pthread_mutex_lock(&secuAdm.mutexSecu);
		for(numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
		{
			while (inSecu.forceInit[numCan])
			{
				CNTLZW(numNode, inSecu.forceInit[numCan]);
				if (numNode == -1)
					break;

				inSecu.forceInit[numCan] &= ~(1 << numNode);
				numAxe = convNodeToAxe(pSecu->axesPlugged, numCan, numNode);
				if (numAxe == -1)
					continue;

				slog(SLOG_WARNING,"Axis %d must be initialized", numAxe);
				SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, DEM_INIT_AXES, 1, (1 << numAxe));
				break;
			}
		}
		pthread_mutex_unlock(&secuAdm.mutexSecu);
	}
	/*---------------------*/
	/* Mise a jour de VAGV */
	/*---------------------*/
	if (pSecu->vagvInt == TRUE)
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, VAGV, VAGV);

	else
		SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, 0, VAGV);

	/*--------------------------------------------------------------------------------*/
	/* Compatibilite avec VISUAL 1 : ce bit est obsolete - utilise dans la conversion */
	/*--------------------------------------------------------------------------------*/
	SrvDonnee_RempliDemEcrit(&demEcrit, wrdSysteme, NIV_MODES, pSecu->bitSansRobot, SANS_ROBOT);

	/*--------------------------------------------------------*/
	/* Ecrit les words systeme modifies au serveur de donnees */
	/*--------------------------------------------------------*/
	if (demEcrit.index)
	{
		statusSrvDonnee = SrvDonnee_ecritGrp(&pSecu->connectServDonnees, &demEcrit, timeout);
		if (statusSrvDonnee.status != pasErreur)
		{
			slog(SLOG_CRITICAL,"System error. Impossible to write in the Data Server. srvStatus is %d", (int)statusSrvDonnee.status);
			SET_ERROR(SERVDON_ERROR, 0, 0);
			pSecu->modeALancer = 0;
		}
		else
		{
			pSecu->nivModes_old = pSecu->nivModes;
			if (!pSecu->reset && (pSecu->nivModes & MASK_MODES_EXEC_MANU))
			{
				pSecu->modeALancer = (pSecu->nivModes & MASK_MODES_EXEC_MANU);
			}
		}
	}
	return(result);
}

/*=====================================================================
  Function Name  : comm_spi
  Description    : communication avec le driver SPI
  Parameter      : pointeur sur la structure de sortie
  Parameter      : timeout du msgSend
  Return         : 0 (ok) ou une valeur negative si erreur
======================================================================*/
int comm_spi(lmob_connexion_t *pConnexionSpi, srvDonneeConnect_t	*connectServDonnees, outSecu_t *pOutSecu, int timeout)
{
	int         result = 0;
	static int  nbErreurSpi = 0;
	static int	bauIhmSim_old = 2;
	static bool	bpValidG_old = 0;
	static bool	bpValidD_old = 0;
	static bool	bauIhm_old   = 0;
	int status = -1;
	lmob_entrees_secu_t msgSpiRx;
	lmob_sorties_secu_t msgSpiTx;
	ecritGrp_t	demEcrit;
	statusSrvDonnee_t	statusSrvDonnee;

	initSrvEcritGrp(&demEcrit);

	msgSpiTx.HM_InhibitionCmde = pOutSecu->enInhibProtect;
	result = lmob_xchSecu(pConnexionSpi, msgSpiTx, &msgSpiRx, &status, timeout);

	if (result < 0)
	{
		nbErreurSpi++;
		if (nbErreurSpi >= MAX_ERROR_SPI_NUMBER)
		{
			slog(SLOG_CRITICAL, "SPI communication error (%s)", strerror(-result));
			if (result == -ETIMEDOUT)
				SET_ERROR(SPI_ERROR, 0, 0);
			else
				SET_ERROR(QNX_ERROR, 0, 0);
		}
		else
		{
			slog(SLOG_WARNING, "SPI communication error (%s)", strerror(-result));
		}
		delay(1);
		return result;
	}
	if (status != OK)
	{
		/*--------------------------------------------------*/
		/* Erreur de communication avec la carte auxiliaire */
		/*--------------------------------------------------*/
		nbErreurSpi++;
		if (nbErreurSpi > MAX_ERROR_SPI_NUMBER)
		{
			slog(SLOG_ERROR, "Internal SPI bus error : corrupted data");
			SET_ERROR(SPI_ERROR, 0, 0);
		}
		else
		{
			slog(SLOG_DEBUG1, "Internal SPI bus error : corrupted data");
		}
		delay(100);
		return result;
	}
	nbErreurSpi = 0;

	if (simu == FALSE)
	{
		/*--------------------------------------------------------------*/
		/* Valorisation des variables utilisees par le thread principal */
		/*--------------------------------------------------------------*/
		pthread_mutex_lock(&secuAdm.mutexSecu);

		inSecu.bpValidG      = (bool)msgSpiRx.hm1;
		inSecu.bpValidD      = (bool)msgSpiRx.hm2;
		inSecu.bauIhm        = (bool)msgSpiRx.au_1;
		inSecu.ihmSurSupport = (bool)msgSpiRx.effetHall;
		inSecu.errorSpi      = (unsigned char)(msgSpiRx.error);

		if (inSecu.errorSpi)
			SET_ERROR(SECU_IHM_ERROR, SECU_SPI, inSecu.errorSpi);

		/*-------------------------------------------*/
		/* Valorisation des compteurs de maintenance */
		/*-------------------------------------------*/
		if (inSecu.bpValidG == TRUE && bpValidG_old == FALSE)
			SrvDonnee_RempliDemEcrit(&demEcrit, wrdMaint, MAINT_BOUTON_HM_G, 1, INST_INCR_COMPTEUR);

		if (inSecu.bpValidD == TRUE && bpValidD_old == FALSE)
			SrvDonnee_RempliDemEcrit(&demEcrit, wrdMaint, MAINT_BOUTON_HM_D, 1, INST_INCR_COMPTEUR);

		if (inSecu.bauIhm == TRUE && bauIhm_old == FALSE)
			SrvDonnee_RempliDemEcrit(&demEcrit, wrdMaint, MAINT_AU, 1, INST_INCR_COMPTEUR);

		pthread_mutex_unlock(&secuAdm.mutexSecu);

		if (demEcrit.index)
		{
			statusSrvDonnee = SrvDonnee_ecritGrp(connectServDonnees, &demEcrit, TIMEOUT_SERVDONNEE);
			if (statusSrvDonnee.status != pasErreur)
			{
				slog(SLOG_CRITICAL,"System error. Impossible to write in the Data Server. srvStatus is %d", (int)statusSrvDonnee.status);
				SET_ERROR(SERVDON_ERROR, 0, 0);
			}
		}
		bpValidG_old = inSecu.bpValidG;
		bpValidD_old = inSecu.bpValidD;
		bauIhm_old   = inSecu.bauIhm;
	}
	else
	{
		/*-----------------*/
		/* Mode Simulation */
		/*-----------------*/
		pthread_mutex_lock(&secuAdm.mutexSecu);

		inSecu.bauIhm        = (bool)msgSpiRx.au_1;
		inSecu.ihmSurSupport = 1;
		inSecu.errorSpi      = 0;

		pthread_mutex_unlock(&secuAdm.mutexSecu);

		if (!inSecu.bauIhm)
		{
			SrvDonnee_SetDefaut(connectServDonnees,D_INTERFACE_BAU_IHM_ENFONCE,0,0);
			if (inSecu.bauIhm != bauIhmSim_old)
				slog(SLOG_INFO,"Safety info. The emergency stop is push");
			bauIhmSim_old = inSecu.bauIhm;
		}
		else if (inSecu.bauIhm != bauIhmSim_old)
		{
			slog(SLOG_INFO,"Safety info. The emergency stop is ok");
			bauIhmSim_old = inSecu.bauIhm;
		}
	}
	return(result);
}

/*=====================================================================
  Function Name  : comm_moduleExecManu
  Description    : communication avec les modules EXEC et MANU
  Parameter      : pointeur sur la strucure locale
  Return         : ok ou erreur
======================================================================*/
int comm_moduleExecManu(secuLoc_t *pSecu)
{
	int result = 0;

	pthread_mutex_lock(&secuAdm.mutexSecu);

	/*-------------------------*/
	/* si demande du mode Exec */
	/*-------------------------*/
	if ((pSecu->modeALancer & MASK_MODES_EXEC) && !pSecu->status.defaut && pSecu->powerOkInt && !pSecu->execEnCours)
	{
		slog(SLOG_INFO,"Launching of the execution of EXEC module");
		inSecu.execEnCours = 1;
		sem_post (&secuAdm.semThreadExec);
	}
	/*---------------------------*/
	/* si demande du mode Manuel */
	/*---------------------------*/
	else if ((pSecu->modeALancer & MASK_MODES_MANU) && !pSecu->status.defaut && pSecu->powerOkInt && !pSecu->manuEnCours)
	{
		slog(SLOG_INFO,"Launching of the execution of MANUEL module");
		inSecu.manuEnCours = 1;
		sem_post (&secuAdm.semThreadManu);
	}
	pthread_mutex_unlock(&secuAdm.mutexSecu);

	return(result);
}

/*=====================================================================
  Function Name  : comm_interface
  Description    : communication avec la carte interface
  Parameter      : pointeur sur la strucure locale
  Parameter      : timeout du msgSend
  Return         : ok ou erreur
======================================================================*/
int comm_interface(secuLoc_t *pSecu, int timeout)
{
	int result = 0;
	int numInt;
	canByte_t msg;
	unsigned short inputInt;
	bool cpuSafetyError;

	/*--------------------------------------------------------------*/
	/* Pour faire retomber la puissance en cas de defauts.          */
	/* Les eventuels defauts generes par l'interface sont masques   */
	/* Les defauts "d'execution" sont egalement masques             */
	/*--------------------------------------------------------------*/
	if (pSecu->status.defaut &&
			(pSecu->status.type != SECU_INT_ERROR) &&
			((pSecu->status.type != DEFAUT_APPLI) || ((pSecu->status.type == DEFAUT_APPLI) && (pSecu->status.diagCode == D_INTERFACE_SECU_BPVALID_RELACHE))))
		cpuSafetyError = TRUE;
	else
		cpuSafetyError = FALSE;

	/*-------------------------------------*/
	/* prepare les infos de secu a envoyer */
	/*-------------------------------------*/
	inputInt  = 0;
	inputInt |= (pSecu->ready          & 1) << 0;
	inputInt |= (pSecu->reset          & 1) << 1;
	inputInt |= (cpuSafetyError        & 1) << 2;
	inputInt |= (pSecu->bauIhm         & 1) << 3;
	inputInt |= (pSecu->bitBauAux      & 1) << 4;
	inputInt |= (pSecu->bitAuAux       & 1) << 5;
	inputInt |= (pSecu->bitProtectAux  & 1) << 6;
	inputInt |= (pSecu->enInhibProtect & 1) << 9;
	inputInt |= (pSecu->protectInhibe  & 1) << 10;
	inputInt |= (pSecu->bpValidG       & 1) << 11;
	inputInt |= (pSecu->bpValidD       & 1) << 11;
	inputInt |= (pSecu->puissanceIhm   & 1) << 12;
	inputInt |= (pSecu->arretCat0      & 1) << 13;
	inputInt |= (pSecu->sansPendant    & 1) << 14;

	/*-------------------------*/
	/* Si le contexte a change */
	/*-------------------------*/
	for(numInt=0; numInt<MAX_INT_NUMBER && secuAdm.nodeInterface[numInt]; numInt++)
	{
		if ((inputInt != pSecu->inputInt[numInt]) || (pSecu->wDogIntCount >= WDOG_INT_PERIODE))
		{
			/*----------------*/
			/* envoi du RPDO1 */
			/*----------------*/
			msg.trame.cob_id  = 0x200 + secuAdm.nodeInterface[numInt];
			msg.trame.dlc     = 3;
			msg.trame.rtr     = 0;
			msg.trame.data[0] = (unsigned char)(inputInt);
			msg.trame.data[1] = (unsigned char)(inputInt >> 8);
			msg.trame.data[2] = 0xAA;

			result = sendMsgCan(msg, secuAdm.busInterface[numInt], pSecu, timeout);

			/*--------------------------------------------------------------*/
			/* mise a jour des donnees si la transmission s'est bien passee */
			/*--------------------------------------------------------------*/
			if (result == 0)
				pSecu->inputInt[numInt] = inputInt;
		}
	}
	return(result);
}

/*=====================================================================
  Function Name  : comm_moduleAxe
  Description    : communication avec le module d'axe
  Parameter      : pointeur sur la strucure locale
  Parameter      : timeout du msgSend
  Return         : ok ou erreur
======================================================================*/
int comm_moduleAxe(secuLoc_t *pSecu, int timeout)
{
	int result = 0;
	recInputBuf_t msgAxe;
	int repMsgAxe;
	unsigned long secu;

	/*----------------------------------*/
	/* On sort s'il n'y a pas d'axe can */
	/*----------------------------------*/
	if (secuAdm.axePresent == 0)
		return result;

	/*------------------------------*/
	/* Envoi periodique du bit Secu */
	/*------------------------------*/
	if (simu == FALSE)
		secu = 0xFFFFFFFF;
	else
		secu = 0;

	/*----------------*/
	/* Arrêt des axes */
	/*-----------------*/
	msgAxe.TypeCmd = CMD_SECU;
	//	msgAxe.inputData.Commande = (pSecu->stopAxes | (~pSecu->axesPlugged)) & secu;
	msgAxe.inputData.Commande = (pSecu->powerOkInt?0:0xFFFFFFFF);		// Pour DEIMO
	result = MsgSendPlus(pSecu->coidModuleAxe, &msgAxe, sizeof(msgAxe), &repMsgAxe, sizeof(repMsgAxe), timeout);

	if (result == -ETIMEDOUT)
	{
		slog(SLOG_ERROR,"Axes module communication error (%s)", strerror(-result));
		SET_ERROR(AXE_ERROR, 0, 0);
	}
	else if (result < 0)
	{
		slog(SLOG_CRITICAL,"Axes module communication error (%s)", strerror(-result));
		SET_ERROR(QNX_ERROR, 0, 0);
	}
	return(result);
}

/*=====================================================================
  Function Name  : comm_variateur
  Description    : communication avec les variateurs
  Parameter      : pointeur sur la strucure locale
  Parameter      : timeout du msgSend
  Return         : ok ou erreur
======================================================================*/
int comm_variateur(secuLoc_t *pSecu, int timeout)
{
	int result = 0;
	canByte_t msg;
	int numCan;
	int numNode;
	int nodes;
	unsigned short controlWord;
	unsigned short statusWord = 0;
	int envoiCtrlWord = 0;
	int newState = 0;

	/*----------------------------------*/
	/* On sort s'il n'y a pas d'axe can */
	/*----------------------------------*/
	if (secuAdm.axePresent == 0)
		return result;

	/*-----------------------------*/
	/* Calcul des noeuds a stopper */
	/*-----------------------------*/
	if (pSecu->axesPlugged != pSecu->axesPlugged_old || pSecu->stopAxes != pSecu->stopAxes_old){
		convAxeToNode (pSecu->axesPlugged, pSecu->stopAxes, &pSecu->stopNodes[0]);
		pSecu->axesPlugged_old = pSecu->axesPlugged;
		pSecu->stopAxes_old = pSecu->stopAxes;
		newState = 1;
		slog(SLOG_DEBUG1,"axesPlugged = 0x%x, stopAxes = 0x%x, stopNodes[0] = 0x%x, stopNodes[1] = 0x%x", pSecu->axesPlugged, pSecu->stopAxes, pSecu->stopNodes[0], pSecu->stopNodes[1]);
		slog(SLOG_DEBUG1,"nodesPlugged[0] = 0x%x, nodesPlugged[1] = 0x%x, nodesUncontrolled[0] = 0x%x, nodesUncontrolled[1] = 0x%x", pSecu->nodesPlugged[0], pSecu->nodesPlugged[1], pSecu->nodesUncontrolled[0], pSecu->nodesUncontrolled[1]);
	}
	/*----------------------------------*/
	/* Recherche des composants de secu */
	/*----------------------------------*/
	for(numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
	{
		nodes  = secuAdm.nodesSecu[numCan];
		while (nodes)
		{
			CNTLZW(numNode, nodes);
			if (numNode == -1)
				break;

			/*---------------------------------------------*/
			/* si c'est un variateur et qu'il est connecte */
			/*---------------------------------------------*/
			if ((secuAdm.typeNode[numCan][numNode] & TYP_NOD_CAN) == ID_NOD_CAN_VAR)
			{
				pthread_mutex_lock(&secuAdm.mutexSecu);
				statusWord  = inSecu.statusWord[numCan][numNode];
				controlWord = inSecu.controlWord[numCan][numNode];
				pthread_mutex_unlock(&secuAdm.mutexSecu);
				/*---------------------------------------------------------------*/
				/* test si le variateur a pris en compte le VAGV et le quickstop */
				/*---------------------------------------------------------------*/
				if (pSecu->enInhibProtect && !(statusWord  & STATUS_WORD_NOT_VAGV))
				{
					controlWord &= ~CTRL_WORD_VAGV;
					envoiCtrlWord = 1;
				}
				/* il ne faut pas envoyer de quickstop au variateur Deimo */
				/* l'arrêt est gere par le module axe */
				if ((secuAdm.typeNode[numCan][numNode] & TYP_VAR_CAN) != ID_DEIMO)
				{
					if (((pSecu->stopNodes[numCan]         >> numNode) & 1) ||			// si le noeud doit etre stoppe
						((pSecu->nodesUncontrolled[numCan] >> numNode) & 1) || 			// ou si le noeud est non controle
					   !((pSecu->nodesPlugged[numCan]      >> numNode) & 1))   			// ou si le noeud est deconnecte
					{
						if ((statusWord & STATUS_WORD_NOT_QUICKSTOP) || newState)
						{
							controlWord &= ~CTRL_WORD_NOT_QUICKSTOP; /* stop */
							envoiCtrlWord = 1;
						}
					}
				}
				/*-------------------------------------------------------------------------------*/
				/* Lors d'un reset, les limites des axes non initialises ou forces sont inhibees */
				/*-------------------------------------------------------------------------------*/
				if (pSecu->reset)
				{
					controlWord |= CTRL_WORD_RESET_FAULT;
					if ((((pSecu->etatInitNodes[numCan] >> numNode) & 1) == FALSE) || pSecu->forceDeplacement)
					{
						controlWord |= CTRL_WORD_OUT_OF_LIMIT;
					}
					envoiCtrlWord = 1;
					slog(SLOG_DEBUG1,"reset drive");
				}
				/*----------------*/
				/* envoi du RPDO1 */
				/*----------------*/
				if (envoiCtrlWord && (pSecu->nodesUncontrolled[numCan] != BUS_NON_CONTROLE))
				{
					/* Modif du 03/08/12 pour utiliser un autre PDO pour DEIMO */
					if ((secuAdm.typeNode[numCan][numNode] & TYP_VAR_CAN) == ID_INFRANOR)
						msg.trame.cob_id  = 0x200 + numNode + 1;
					else if ((secuAdm.typeNode[numCan][numNode] & TYP_VAR_CAN) == ID_DEIMO)
						msg.trame.cob_id  = 0x400 + numNode + 1;

					msg.trame.dlc     = 2;
					msg.trame.rtr     = 0;
					msg.trame.data[0] = (unsigned char)(controlWord);
					msg.trame.data[1] = (unsigned char)(controlWord >> 8);
					msg.trame.data[2] = 0;
					msg.trame.data[3] = 0;
					msg.trame.data[4] = 0;
					msg.trame.data[5] = 0;
					msg.trame.data[6] = 0;
					msg.trame.data[7] = 0;

					result = sendMsgCan(msg, numCan, pSecu, timeout);
					envoiCtrlWord = 0;
				}
				/*------------------------------------------------------*/
				/* demande l'etat des entrees STO des Infranor via SDO2 */
				/*------------------------------------------------------*/
				if (((pSecu->demEtatSto[numCan] >> numNode) & 1) && (secuAdm.typeNode[numCan][numNode] & TYP_VAR_CAN) == ID_INFRANOR)
				{
					msg.trame.cob_id  = 0x640 + numNode + 1;
					msg.trame.dlc     = 8;
					msg.trame.rtr     = 0;
					msg.trame.data[0] = 0x40;	/* initiate upload */
					msg.trame.data[1] = 0x01;	/* object 0x3001 */
					msg.trame.data[2] = 0x30;	/* object 0x3001 */
					msg.trame.data[3] = 0x04;	/* Sub-index 0x04 */
					msg.trame.data[4] = 0;
					msg.trame.data[5] = 0;
					msg.trame.data[6] = 0;
					msg.trame.data[7] = 0;

					result = sendMsgCan(msg, numCan, pSecu, timeout);
				}
			}
			pSecu->demEtatSto[numCan] &= ~(1 << numNode);
			nodes &= ~(1 << numNode);
		}
	}
	/*--------------------------------------*/
	/* Recherche des composants deconnectes */
	/*--------------------------------------*/
	for(numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
	{
		nodes = ~pSecu->nodesPlugged[numCan];

		while (nodes)
		{
			CNTLZW(numNode, nodes);
			if (numNode == -1)
				break;

			/*-----------------------*/
			/* si c'est un variateur */
			/*-----------------------*/
			if ((secuAdm.typeNode[numCan][numNode] & TYP_NOD_CAN) == ID_NOD_CAN_VAR)
			{
				/*-------------------------------------------------------------*/
				/* Reset des eventuels defauts suite a la deconnection de l'axe */
				/*-------------------------------------------------------------*/
				controlWord = 0;

				/*----------------*/
				/* envoi du RPDO1 */
				/*----------------*/
				if (pSecu->nodesUncontrolled[numCan] != BUS_NON_CONTROLE)
				{
					/* Modif du 03/08/12 pour utiliser un autre PDO pour DEIMO */
					if ((secuAdm.typeNode[numCan][numNode] & TYP_VAR_CAN) == ID_INFRANOR)
						msg.trame.cob_id  = 0x200 + numNode + 1;
					else if ((secuAdm.typeNode[numCan][numNode] & TYP_VAR_CAN) == ID_DEIMO)
						msg.trame.cob_id  = 0x400 + numNode + 1;

					msg.trame.dlc     = 2;
					msg.trame.rtr     = 0;
					msg.trame.data[0] = (unsigned char)(controlWord);
					msg.trame.data[1] = (unsigned char)(controlWord >> 8);
					msg.trame.data[2] = 0;
					msg.trame.data[3] = 0;
					msg.trame.data[4] = 0;
					msg.trame.data[5] = 0;
					msg.trame.data[6] = 0;
					msg.trame.data[7] = 0;

					result = sendMsgCan(msg, numCan, pSecu, timeout);
				}
				controlWord |= CTRL_WORD_RESET_FAULT;

				/*----------------*/
				/* envoi du RPDO1 */
				/*----------------*/
				if (pSecu->nodesUncontrolled[numCan] != BUS_NON_CONTROLE)
				{
					msg.trame.data[0] = (unsigned char)(controlWord);
					msg.trame.data[1] = (unsigned char)(controlWord >> 8);

					result = sendMsgCan(msg, numCan, pSecu, timeout);
				}
			}
			nodes &= ~(1 << numNode);
		}
	}
	return(result);
}

/*=====================================================================
  Function Name  : comm_staubli
  Description    : communication avec staubli
  Parameter      : pointeur sur la structure d'entree et la strucure de sortie
  Return         : ok ou erreur
======================================================================*/
int comm_staubli(inSecu_t *pInSecu, outSecu_t *pOutSecu)
{
#define ERROR_TRAME_ACCEPTED	3	// trames mauvaise a suivre acceptees
	int result = 0;
	secuToVal3_t toStaubli;
	val3ToSecu_t fromStaubli;
	static long watchDogSecu = 1;
	int error = 0;
	static int nbErrorTrame = 0;
	static int nbErrorComm = 0;
	static int acquit = 0;

	watchDogSecu = (0 == watchDogSecu)? 1 : 0;

	toStaubli.puissanceOff = (0 == pOutSecu->stopAxes)? 0 : 1;
	toStaubli.watchDog = watchDogSecu;
	toStaubli.VAGVenable = (pOutSecu->enInhibProtect)? 0 : 1;
	toStaubli.acquit = acquit;// (long)pOutSecu->reset;

	fromStaubli.watchDog = watchDogSecu;
	fromStaubli.esStatus = 0;
	fromStaubli.hardwareFault = 0;
	fromStaubli.numDefaut = staubliTrame;

	if (ERROR == lib6x_envoiSecu(&toStaubli, &fromStaubli))
	{
		nbErrorComm++;
		error = 1;
		slog(SLOG_WARNING,"nbErrorComm %d", nbErrorComm);
		if (nbErrorComm > ERROR_TRAME_ACCEPTED)
		{
			SET_ERROR(SECU_STAUBLI_ERROR, GEST_COMM, 0);
			slog(SLOG_WARNING,"libStaubliSecuEnvoi has returned an error");
			result = 1;
		}
	}
	else
	{
		nbErrorComm = 0;
	}
	if (error == 0)
	{
		if (fromStaubli.numDefaut == staubliTrame && nbErrorTrame < ERROR_TRAME_ACCEPTED)
		{
			nbErrorTrame++;
			slog(SLOG_WARNING,"nbErrorTrame %d", nbErrorTrame);
		}
		else
		{
			if (fromStaubli.watchDog != watchDogSecu && nbErrorTrame == 0)
			{
				error = 1;
				SET_ERROR(SECU_STAUBLI_ERROR, GEST_WDOG, 0);
				slog(SLOG_WARNING,"SECU_STAUBLI_ERROR");
			}
			if (fromStaubli.hardwareFault)
			{
				error = 1;
				SET_ERROR(SECU_STAUBLI_ERROR, GEST_HARDWARE_ERROR, fromStaubli.hardwareFault);
				slog(SLOG_WARNING,"fromStaubli.hardwareFault = %d", fromStaubli.hardwareFault);
				lib6x_acquitHardwareFault();
			}
			if (fromStaubli.numDefaut > 0)
			{
				slog(SLOG_WARNING,"fromStaubli.numDefaut = %d", fromStaubli.numDefaut);
				error = 1;
				switch(fromStaubli.numDefaut)
				{
				case staubliOK: 		break;
				case staubliWatchdog:	SET_ERROR(SECU_STAUBLI_ERROR, GEST_WDOG, 0);	break;
				case staubliTimeOut:	SET_ERROR(SECU_STAUBLI_ERROR, GEST_WDOG, 0);	break;
				case staubliNoTrame:	SET_ERROR(SECU_STAUBLI_ERROR, GEST_WDOG, 0);	break;
				case staubliComm:		SET_ERROR(SECU_STAUBLI_ERROR, GEST_COMM, 0);	break;
				case staubliTrame :		SET_ERROR(SECU_STAUBLI_ERROR, GEST_COMM, 0);	break;
				case staubliVAGV :		SET_ERROR(SECU_STAUBLI_ERROR, GEST_COMM, 0);	break;
				}
			}
			pInSecu->powerOkStaubli = (bool)fromStaubli.puissance;
			nbErrorTrame = 0;
		}
	}
	if (error == 1)
	{
		acquit = 1;
		slog(SLOG_INFO,"Acquit");
	}
	else
	{
		acquit = 0;
	}
	return result;
}

/**
 * @brief envoi des messages vers vnc-display et IHM
 * @param arg pointeur sur une structure secuLoc_t qui encapsule les variables SECU
 *
 * La liaison QNET/Ethernet entre la CPU et le Pendant
 * n'est pas fiable et très lente. Pour éviter de bloquer
 * le thread principal, le MsgSend est réalisé dans un
 * thread auxiliaire. Pas terrible...
 */
static void *thread_comm_vncDisplay(void *arg)
{
	int r;
	secuLoc_t *pSecu = (secuLoc_t *)arg;
	display_msg_t msg_vnc;

	pthread_setname_np(pthread_self(), __FUNCTION__);
	while(1) {
		memset(&msg_vnc, 0, sizeof(msg_vnc));
		r = fifoPlus_getWait(fifo_thread_vnc, (unsigned char *)&msg_vnc.mode);
		if (r == ERROR) {
			slog(SLOG_CRITICAL, "Internal error, thread stopped");
			break;
		}
		slog(SLOG_INFO,"switching display's mode (%d)", msg_vnc.mode);
		r = MsgSendPlus((int)pSecu->coidVncDisplay, &msg_vnc, sizeof(display_msg_t), NULL, 0, 1000);
		if (r < 0) {
			/* erreur de communication */
			switch(r) {
			case -ETIMEDOUT:
				SET_ERROR(VNC_ERROR, 0, 0);
				break;
			default:
				SET_ERROR(QNX_ERROR, 0, 0);
				break;
			}
			slog(SLOG_CRITICAL,"Communication error with VNC_display");
			continue;
		}
		r = MsgSendPlus((int)pSecu->coidIhmDisplay, &msg_vnc, sizeof(display_msg_t), NULL, 0, 1000);
		if (r < 0) {
			/* erreur de communication */
			switch(r) {
			case -ETIMEDOUT:
				SET_ERROR(VNC_ERROR, 0, 0);
				break;
			default:
				SET_ERROR(QNX_ERROR, 0, 0);
				break;
			}
			slog(SLOG_CRITICAL,"Communication error with VNC_display");
			continue;
		}
	}
	return NULL;
}

/**
 * @brief Communication avec VNC display et l'IHM
 * @return OK
 *
 * Active l'affichage de l'IHM sur le pendant ou sur le pupitre presse
 *
 * Le thread principal dépose une commande dans la fifo
 * "fifo_thread_vnc" avec la fonction comm_vncDisplay()
 *
 * la fifo est ensuite vidée par le thread_comm_vncDisplay
 *
 * Cette fonction surveille également que la fifo se vide
 * dans un délai raisonnable (500 ms). Sinon, c'est
 * que la communication CPU/Pendant est coincée. Il
 * faut lever un défaut.
 *
 */
int comm_vncDisplay (void)
{
	static unsigned compteur = 0;
	static display_mode_t old_mode_vnc = -1;
	display_mode_t mode;
	int r;

	pthread_mutex_lock(&secuAdm.mutexSecu);
	if (old_mode_vnc != outSecu.modeVnc) {
		/* un changement de mode est demandé ! */
		old_mode_vnc = outSecu.modeVnc;
		r = fifoPlus_put(fifo_thread_vnc, (const unsigned char *)&outSecu.modeVnc);
		if (r == ERROR) {
			/* fifo pleine ! */
			SET_ERROR(VNC_ERROR, 0, 0);
			slog(SLOG_ERROR, "Communication with vnc-display and GUI lost !");
		}
	}
	pthread_mutex_unlock(&secuAdm.mutexSecu);
	/*
	 * On surveille que le thread auxiliaire fonctionne bien.
	 * Si la fifo ne se vide pas assez vide, il y a un problème
	 * pour communiquer avec vnc-display et GUI
	 */
	if (fifoPlus_nb(fifo_thread_vnc) > 0)
		compteur++;
	else
		compteur = 0;
	if (compteur > 25) {
		SET_ERROR(VNC_ERROR, 0, 0);
		slog(SLOG_ERROR, "Communication with vnc-display and GUI lost !");
		/* vide la fifo */
		while (fifoPlus_get(fifo_thread_vnc, (unsigned char *)&mode) != ERROR);
	}
	return OK;
}

/*=====================================================================
  Function Name  : thread_driverSpi
  Description    : Ce thread recupere les entrees du pendant.
  Parameter      : None
  Return         : None
======================================================================*/
void *thread_spi (void *arg)
{
	void *cp_arg = arg;
	cp_arg = NULL;
	bool sansPendant = TRUE;
	bool miseSousTension = TRUE;
	statusSrvDonnee_t statusSrvDonnee;
	srvDonneeConnect_t connectServDonnees;
	lmob_connexion_t connexionSpi;

	pthread_setname_np(pthread_self(),"thread_spi");

	/*--------------------------------------*/
	/* Connexion avec le serveur de donnees */
	/*--------------------------------------*/
	slog(SLOG_INFO,"Connection with Data Server");
	statusSrvDonnee = SrvDonnee_init(MOD_SECU,&connectServDonnees,ptTableau);

	if (statusSrvDonnee.status != pasErreur)
	{
		slog(SLOG_CRITICAL,"Data server connection error");
		SET_ERROR(QNX_ERROR, 0, 0);
		while(1)
			delay(1000);
	}
	/*------------------------------*/
	/* Connexion avec le Driver SPI */
	/*------------------------------*/
	slog(SLOG_INFO,"Connection with SPI driver");

	lmob_init(&connexionSpi);

	if (lmob_Connecter(&connexionSpi, 0) != 0)
	{
		slog(SLOG_CRITICAL,"SPI connection error");
		SET_ERROR(QNX_ERROR, 0, 0);
		while(1)
			delay(1000);
	}
	while(1)
	{
		do
		{
			pthread_mutex_lock(&secuAdm.mutexSecu);
			inSecu.timeSpi = ClockCycles();

			/*----------------------------*/
			/* Recupere l'etat du pendant */
			/*----------------------------*/
			sansPendant = inSecu.sansPendant;
			if (!sansPendant)
				miseSousTension = FALSE;

			pthread_mutex_unlock(&secuAdm.mutexSecu);

			/*------------------------------*/
			/* Communication avec le driver */
			/*------------------------------*/
			sem_wait(&secuAdm.semComSpi);
			comm_spi(&connexionSpi, &connectServDonnees, &outSecu, TIMEOUT_DRIVER_SPI);

			while (sem_trywait(&secuAdm.semComSpi) == 0);
			delay(10);

		} while(!sansPendant || miseSousTension);
		/*------------------------------------------------*/
		/* Arret du thread si le pendant a ete deconnecte */
		/*------------------------------------------------*/
		/* deconnexion */
		slog(SLOG_INFO,"disconnection with SPI driver");
		pthread_mutex_lock(&secuAdm.mutexSecu);
		inSecu.threadSpiStopped = TRUE;
		pthread_mutex_unlock(&secuAdm.mutexSecu);
		if (lmob_Deconnecter(&connexionSpi) != 0)
		{
#ifdef __ARM__
			slog(SLOG_CRITICAL,"SPI disconnection error");
			SET_ERROR(QNX_ERROR, 0, 0);
#else
			/* sur PEV2, le module "driverSpi" ne supporte pas bien le name_close() */
			slog(SLOG_WARNING,"SPI disconnection error");
#endif
		}
		/* attente de reconnexion */
		sem_wait (&secuAdm.semThreadSpi);
		/* connexion */
		slog(SLOG_INFO,"Connection with SPI driver");
		if (lmob_Connecter(&connexionSpi, 0) != 0)
		{
			slog(SLOG_CRITICAL,"SPI connection error");
			SET_ERROR(QNX_ERROR, 0, 0);
		}
		pthread_mutex_lock(&secuAdm.mutexSecu);
		inSecu.threadSpiStopped = FALSE;
		pthread_mutex_unlock(&secuAdm.mutexSecu);
	}
	return NULL;
}

/*=====================================================================
  Function Name  : thread_ctrlExec
  Description    : Ce thread contrele l'execution du module Exec.
  Parameter      : None
  Return         : None
=====================================================================*/
void *thread_ctrlExec (void *arg)
{
	void *cp_arg = arg;
	cp_arg = NULL;
	int result;
	msgExec_t msgExec;
	static int coidModuleExec;

	pthread_setname_np(pthread_self(),"thread_ctrlExec");

	/*-------------------------------*/
	/* Connexion avec le Module Exec */
	/*-------------------------------*/
	slog(SLOG_INFO,"Connection with EXEC module");

	if ((coidModuleExec = name_open(CANAL_EXEC, 0)) == -1)
	{
		slog(SLOG_CRITICAL,"EXEC module connection error");
		SET_ERROR(QNX_ERROR, 0, 0);
		while (1)
			delay(1000);
	}
	msgExec.cmde = 0x0A0A0A0A;

	while(1)
	{
		/*------------------------------------------*/
		/* Synchronisation avec le thread principal */
		/*------------------------------------------*/
		sem_wait (&secuAdm.semThreadExec);

		/*-------------------------------*/
		/* Lance et attend la fin d'Exec */
		/*-------------------------------*/
		result = MsgSendPlus(coidModuleExec, &msgExec, sizeof(msgExec), NULL, 0, 0);

		if (result < 0)
		{
			slog(SLOG_CRITICAL,"EXEC module communication error (%s)", strerror(-result));
			SET_ERROR(QNX_ERROR, 0, 0);
		}
		else
		{
			pthread_mutex_lock(&secuAdm.mutexSecu);
			inSecu.execEnCours = 0;
			pthread_mutex_unlock(&secuAdm.mutexSecu);
		}
	}
	return NULL;
}

/*=====================================================================
  Function Name  : thread_ctrlManu
  Description    : Ce thread contrele l'execution du module Manuel.
  Parameter      : None
  Return         : None
=====================================================================*/
void *thread_ctrlManuel (void *arg)
{
	void *cp_arg = arg;
	cp_arg = NULL;
	int result;
	msgManuel_t msgManuel;
	static int coidModuleManu;

	pthread_setname_np(pthread_self(),"thread_ctrlManuel");

	/*---------------------------------*/
	/* Connexion avec le Module Manuel */
	/*---------------------------------*/
	slog(SLOG_INFO,"Connection with MANUEL module");

	if ((coidModuleManu = name_open(CANAL_MANUEL, 0)) == -1)
	{
		slog(SLOG_CRITICAL,"MANUEL module connection error");
		SET_ERROR(QNX_ERROR, 0, 0);
		while (1)
			delay(1000);
	}
	msgManuel.cmde = 0x0A0A0A0A;

	while(1)
	{
		/*------------------------------------------*/
		/* Synchronisation avec le thread principal */
		/*------------------------------------------*/
		sem_wait (&secuAdm.semThreadManu);

		/*----------------------------------*/
		/* Lance et attend la fin de Manuel */
		/*----------------------------------*/
		result = MsgSendPlus(coidModuleManu, &msgManuel, sizeof(msgManuel), NULL, 0, 0);

		if (result < 0)
		{
			slog(SLOG_CRITICAL,"MANUEL module communication error (%s)", strerror(-result));
			SET_ERROR(QNX_ERROR, 0, 0);
		}
		else
		{
			pthread_mutex_lock(&secuAdm.mutexSecu);
			inSecu.manuEnCours = 0;
			pthread_mutex_unlock(&secuAdm.mutexSecu);
		}
	}
	return NULL;
}

/*=====================================================================
  Function Name  : thread_servDonnees
  Description    : Ce thread assure la communication avec le serveur
                   de donnees.
  Parameter      : None
  Return         : None
=====================================================================*/
void *thread_servDonnees (void *arg)
{
	void *cp_arg = arg;
	cp_arg = NULL;
	bool demChgInhibProtect;
	bool enInhibProtect;
	unsigned long memNumProfilEnCours;
	unsigned long memNodesUncontrolled[MAX_BUS_NUMBER];
	statusSrvDonnee_t statusSrvDonnee;
	srvDonneeConnect_t connectServDonnees;
	srvDonneeConnect_t *connection;

	memNumProfilEnCours     = 0;
	memNodesUncontrolled[0] = 0;
	memNodesUncontrolled[1] = 0;
	connection = &connectServDonnees;

	pthread_setname_np(pthread_self(),"thread_servDonnees");

	/*--------------------------------------*/
	/* Connexion avec le serveur de donnees */
	/*--------------------------------------*/
	statusSrvDonnee = SrvDonnee_init(MOD_SECU,&connectServDonnees, ptTableau);

	if (statusSrvDonnee.status != pasErreur)
	{
		slog(SLOG_CRITICAL,"Data server connection error");
		while(1)
			delay(1000);
	}
	while(1)
	{
		statusSrvDonnee = SrvDonnee_lectChgt(&connectServDonnees, MSG_TYPE(wrdSysteme) | MSG_TYPE(wrdStep) | MSG_TYPE(wrdSysteme1), 0);

		if (statusSrvDonnee.status != pasErreur)
		{
			slog(SLOG_CRITICAL,"System error. The Data Server generated an error during a reading on change. srvStatus is %d", (int)statusSrvDonnee.status);
			SET_ERROR(SERVDON_ERROR, 0, 0);
			delay(10);
		}
		else
		{
			/*--------------------------------------------------------------*/
			/* Valorisation des variables utilisees par le thread principal */
			/*--------------------------------------------------------------*/
			pthread_mutex_lock(&secuAdm.mutexSecu);

			/*------------------------------------------*/
			/* Regarde si les etats des axes ont change */
			/*------------------------------------------*/
			if (inSecu.axesPlugged != pTAB_OFFSET(wrdSysteme, AXES_PLUGGED))
			{
				inSecu.axesPlugged    = pTAB_OFFSET(wrdSysteme, AXES_PLUGGED);
				convAxeToNode (inSecu.axesPlugged, inSecu.axesPlugged, &inSecu.nodesPlugged[0]);
				secuAdm.flagMajFilter  = 1;
			}
			if (inSecu.etatInitAxes != pTAB_OFFSET(wrdSysteme, ETATS_INIT_AXES))
			{
				inSecu.etatInitAxes    = pTAB_OFFSET(wrdSysteme, ETATS_INIT_AXES);
				convAxeToNode (inSecu.axesPlugged, inSecu.etatInitAxes, &inSecu.etatInitNodes[0]);
			}
			/*------------------------------------------------*/
			/* Prise en compte des demandes ou etats de l'IHM */
			/*------------------------------------------------*/
			inSecu.demChgModesLoc       = pTAB_OFFSET(wrdSysteme, DEM_CHG_MODES_LOCAL);
			inSecu.demChgModesExt       = pTAB_OFFSET(wrdSysteme, DEM_CHG_MODES_EXT);
			inSecu.nivModesEnCours      = pTAB_OFFSET(wrdSysteme, NIV_MODES);
			inSecu.numDefEnCours        = pTAB_OFFSET(wrdSysteme, DEFAUT_EN_COURS);
			inSecu.effetdefEnCours      = getDefautEffetMode(inSecu.numDefEnCours, inSecu.nivModesEnCours);;
			inSecu.etatCycle2           = pTAB_OFFSET(wrdSysteme, ETATS_CYCLE_2);
			inSecu.forceDeplacement     = (bool)((pTAB_OFFSET(wrdSysteme, CMDES_MANUEL_2)) & DEPL_HORS_CAME);
			inSecu.sansPendant          = (bool)((pTAB_OFFSET(wrdSysteme, ETATS_PENDANT))  & SANS_PENDANT);
			inSecu.nodesUncontrolled[0] = pTAB_OFFSET(wrdSysteme, NOEUDS_NON_CONTROLES_CAN_0);
			inSecu.nodesUncontrolled[1] = pTAB_OFFSET(wrdSysteme, NOEUDS_NON_CONTROLES_CAN_1);
			inSecu.numProfilEnCours     = pTAB_OFFSET(wrdSysteme, NUM_PROFIL_EN_COURS);
			inSecu.bitSansRobot         = pTAB_OFFSET(wrdSysteme, ETATS_PRESSE1) & PRESSE_EN_SS_ROBOT;
			inSecu.numPopup             = pTAB_OFFSET(wrdSysteme, QUESTION_CPU2IHM);

			/* Mise "sous"/hors puissance */
			if ((inSecu.demChgModesLoc & LOCAL_DEM_POWER_OFF) || (inSecu.demChgModesExt & EXT_DEM_POWER_OFF))
				inSecu.puissanceIhm = FALSE;
			else if ((inSecu.demChgModesLoc & LOCAL_DEM_POWER_ON) || (inSecu.demChgModesExt & EXT_DEM_POWER_ON))
				inSecu.puissanceIhm = TRUE;

			/* Etat du pendant */
			if (inSecu.sansPendant == TRUE)
				inSecu.timeSpi = ClockCycles();

			if (pTAB_OFFSET(wrdSysteme, NUM_PRG_COURANT) != PAS_DE_PRG_SELECTIONNE)
				inSecu.prgSelectionne  = TRUE;
			else
				inSecu.prgSelectionne  = FALSE;

			/* Prise en compte des défauts */
			if (inSecu.effetdefEnCours == DEF_ARRET && (pTAB_OFFSET(wrdStep,CMDES_MANUEL_2) & DEPL_HORS_CAME))
				inSecu.effetdefEnCours = DEF_WARNING;

			if (inSecu.effetdefEnCours == DEF_ARRET)
				SET_ERROR(DEFAUT_APPLI, 0, inSecu.numDefEnCours);
			else if (inSecu.effetdefEnCours >= DEF_ARRET)
				SET_ERROR(DEFAUT_SECU, 0, inSecu.numDefEnCours);

			/*------------------------------------------------------------------*/
			/* Valorisation d'une variable pour la demande du "mode" Inhibition */
			/* car l'IHM gere une demande de type Flip Flop                     */
			/*------------------------------------------------------------------*/
			demChgInhibProtect = (bool)(inSecu.demChgModesLoc  & LOCAL_DEM_INHIB_PROTECT);
			enInhibProtect     = (bool)(inSecu.nivModesEnCours & EN_INHIB_PROTECT );

			if (TRUE == demChgInhibProtect && 0 == inSecu.memDemChgInhibProtect)
			{
				inSecu.memDemChgInhibProtect = 1;
				if (enInhibProtect)
					inSecu.demInhibProtect = FALSE;
				else
					inSecu.demInhibProtect = TRUE;
				slog(SLOG_DEBUG1,"inSecu.demInhibProtect = %d", inSecu.demInhibProtect);
			} else if (FALSE == demChgInhibProtect) {
				inSecu.memDemChgInhibProtect = 0;
			}
			/*--------------------------------------*/
			/* Etat du verrouillage des protecteurs */
			/*--------------------------------------*/
			if (getParam(secuAdm.bdp, G_CFGIO, F_GESTION_GACHE1, I_GACHE_FCT) != GACHE_SANS){
				inSecu.demVerrouGache1 = (bool)((pTAB_OFFSET(wrdSysteme, WORD_SECURITE)) & DEM_VERROUILLAGE_GACHE1);
			}
			else{
				inSecu.demVerrouGache1 = 0;
			}
			if (getParam(secuAdm.bdp, G_CFGIO, F_GESTION_GACHE2, I_GACHE_FCT) != GACHE_SANS){
				inSecu.demVerrouGache2 = (bool)((pTAB_OFFSET(wrdSysteme, WORD_SECURITE)) & DEM_VERROUILLAGE_GACHE2);
			}
			else{
				inSecu.demVerrouGache2 = 0;
			}
			/*-----------------------------------------------------------------*/
			/* Rappel a chaque chgt de profil que des noeuds sont non controle */
			/*-----------------------------------------------------------------*/
			if ((inSecu.nodesUncontrolled[0] || inSecu.nodesUncontrolled[1]) && (inSecu.numProfilEnCours != memNumProfilEnCours))
			{
				SET_ERROR(SECU_CPU_ERROR, GEST_NODE, 0);
				memNumProfilEnCours = inSecu.numProfilEnCours;
			}
			pthread_mutex_unlock(&secuAdm.mutexSecu);
		}
		delay(5);
	}
	return NULL;
}

/*=====================================================================
  Function Name  : thread_staubli
  Description    : Ce thread assure la communication avec staubli
  Parameter      : None
  Return         : None
=====================================================================*/
void *thread_staubli (void *arg)
{
	void *cp_arg = arg;
	cp_arg = NULL;

	pthread_setname_np(pthread_self(),"thread_staubli");

	while(1)
	{
		sem_wait(&secuAdm.semStaubli);
		inSecu.timeStaubli = ClockCycles();

//		if (simu == FALSE)
			comm_staubli(&inSecu, &outSecu);

		while (sem_trywait(&secuAdm.semStaubli) == 0);
		delay(10);
	}
}

/*=====================================================================
  Function Name  : thread_ctrlMsgOut
  Description    : Ce thread valide les messages Can issues de CanOpen.
  Parameter      : None
  Return         : None
=====================================================================*/
void *thread_ctrlMsgOut (void *arg)
{
	void *cp_arg = arg;
	cp_arg = NULL;
	int result;
	int rcvid;
	canMsg_dem_t canMsgTx_dem;
	canMsg_rep_t canMsgTx_rep;
	struct _msg_info info;
	unsigned char nodeId;
	unsigned short cobId;
	int numCan;
	unsigned short controlWord;
	unsigned char *pDataCanDem;
	unsigned char *pDataCanRep;
	name_attach_t *canalCtrlMsgOut;

	pthread_setname_np(pthread_self(),"thread_ctrlMsgOut");

	result = 0;

	/*----------------------------------------------*/
	/* Canal pour le controle des messages sortants */
	/*----------------------------------------------*/
	canalCtrlMsgOut = name_attach(NULL, CANAL_CTRL_MSG_OUT, 0);
	if (canalCtrlMsgOut == NULL)
	{
		slog(SLOG_CRITICAL,"Channel creation error");
		while (1)
			delay(1000);
	}
	while(1)
	{
		/*-----------------------------------*/
		/* On attend l'emission d'un message */
		/*-----------------------------------*/
		rcvid = MsgReceivePlus(canalCtrlMsgOut->chid, &canMsgTx_dem ,sizeof(canMsg_dem_t), &info, NULL);

		if (rcvid == -1)
		{
			slog(SLOG_CRITICAL,"System error. Remove canalCtrlMsgOut");
			name_detach(canalCtrlMsgOut, 0);
			return EXIT_SUCCESS;
		}

		cobId  = canMsgTx_dem.canMsg[0].trame.cob_id;
		nodeId = canMsgTx_dem.canMsg[0].trame.cob_id & 0x7F;
		numCan = canMsgTx_dem.numCan;

		memcpy(&canMsgTx_rep.canMsg, &canMsgTx_dem.canMsg, sizeof(canByte_t));
		canMsgTx_rep.status = 0;

		/*--------------------------------------*/
		/* si c'est un variateur (control word) */
		/*--------------------------------------*/
		if ((secuAdm.typeNode[numCan][nodeId-1] & TYP_NOD_CAN) == ID_NOD_CAN_VAR)
		{
			pDataCanDem = 0;
			pDataCanRep = 0;
			pthread_mutex_lock(&secuAdm.mutexSecu);

			/*---------------------------------------------------------------*/
			/* reception du control word via un PDO (hors arret de securite) */
			/*---------------------------------------------------------------*/
			if (((cobId & 0x780) == 0x200) ||
					((cobId & 0x780) == 0x300))
			{
				pDataCanDem = &canMsgTx_dem.canMsg[0].trame.data[0];
				pDataCanRep = &canMsgTx_rep.canMsg.trame.data[0];
			}
			/*---------------------------------------------------------------*/
			/* reception du control word via un SDO (hors arret de securite) */
			/*---------------------------------------------------------------*/
			else if ((cobId & 0x780) == 0x600)
			{
				pDataCanDem = &canMsgTx_dem.canMsg[0].trame.data[4];
				pDataCanRep = &canMsgTx_rep.canMsg.trame.data[4];
			}
			if (pDataCanDem != NULL)
			{
				controlWord  = pDataCanDem[0] & 0x00FF;
				controlWord |= pDataCanDem[1] << 8;

				/*-----------------------*/
				/* pour arreter les axes */
				/*-----------------------*/
				/* il ne faut pas envoyer de quickstop au variateur Deimo */
				/* l'arrêt est gere par le module axe */
				if ((secuAdm.typeNode[numCan][nodeId-1] & TYP_VAR_CAN) != ID_DEIMO)
				{
					if (outSecu.stopAxes ||
							((outSecu.nodesUncontrolled[numCan] >> (nodeId-1)) & 1) || // ... ou si le noeud est non contrele
							!((outSecu.nodesPlugged[numCan]      >> (nodeId-1)) & 1))   // ... ou si le noeud est deconnecte
					{
						controlWord &= ~CTRL_WORD_NOT_QUICKSTOP;  /* stop */
					}
				}
				/*---------------------------------------*/
				/* pour valider ou pas la grande vitesse */
				/*---------------------------------------*/
				if (outSecu.enInhibProtect)
				{
					controlWord &= ~CTRL_WORD_VAGV; /* pas vagv */
				}
				else
				{
					controlWord |= CTRL_WORD_VAGV;  /* vagv */
				}
				/*---------------------------------------------*/
				/* pour valider ou pas le contrele des limites */
				/*---------------------------------------------*/
				if (outSecu.forceDeplacement && (outSecu.nivModes != EN_AUTO))
				{
					controlWord |= CTRL_WORD_OUT_OF_LIMIT;  /* controle inactif */
				}
				else if (outSecu.nivModes == EN_AUTO && !(inSecu.etatCycle2 & EN_MODE_INIT))
				{
					controlWord &= ~CTRL_WORD_OUT_OF_LIMIT;  /* controle actif */
				}
				/*---------------------------*/
				/* sauvegarde le controlWord */
				/*---------------------------*/
				inSecu.controlWord[numCan][nodeId-1] = controlWord;

				/*------------------------------*/
				/* ecrit le controlWord modifie */
				/*------------------------------*/
				pDataCanRep[0] = (unsigned char)(controlWord);
				pDataCanRep[1] = (unsigned char)(controlWord >> 8);
			}
			pthread_mutex_unlock(&secuAdm.mutexSecu);
		}
		/*------------------------------*/
		/* si c'est une carte Interface */
		/*------------------------------*/
		else if (secuAdm.typeNode[numCan][nodeId-1] == ID_NOD_CAN_INTERFACE)
		{
			if ((cobId & 0x780) == 0x200) canMsgTx_dem.status = MSG_BLOQUE; /* les messages liesela securite sont bloques */
		}
		/*-------------------*/
		/* Reponse a secuCan */
		/*-------------------*/
		MsgReply(rcvid, 0, &canMsgTx_rep, sizeof(canMsg_rep_t));
	}
}

/*=====================================================================
  Function Name  : thread_ctrlMsgIn
  Description    : Ce thread envoie une copie des messages destines a
                   CanOpen vers Secu.
  Parameter      : None
  Return         : None
=====================================================================*/
void *thread_ctrlMsgIn (void *arg)
{
	void *cp_arg = arg;
	cp_arg = NULL;
	int rcvid;
	unsigned short cobId;
	unsigned char nodeId;
	unsigned long emerCode;
	canMsg_dem_t canMsgRx_dem;
	struct _msg_info info;
	int numCan, n;
	int numInt;
	long vit[MAX_BUS_NUMBER][MAX_NOD_CAN];
	long vit_old[MAX_BUS_NUMBER][MAX_NOD_CAN];
	unsigned long vit_abs;
	unsigned long vit_abs_old;
	unsigned long enMouv[MAX_BUS_NUMBER];
	unsigned long enAccel[MAX_BUS_NUMBER][MAX_NOD_CAN];
	unsigned char stoInput;
	int nbElem;
	unsigned long objet;
	name_attach_t *canalCtrlMsgIn;

	memset(enMouv, 0, sizeof(enMouv));
	memset(vit, 0, sizeof(vit));
	memset(vit_old, 0, sizeof(vit_old));

	pthread_setname_np(pthread_self(),"thread_ctrlMsgIn");

	/* Canal pour le controle des messages entrants */
	canalCtrlMsgIn = name_attach(NULL, CANAL_CTRL_MSG_IN, 0);
	if (canalCtrlMsgIn == NULL)
	{
		slog(SLOG_CRITICAL,"Channel creation error");
		while (1)
			delay(1000);
	}
	while(1)
	{
		/* On attend la reception d'un message */
		rcvid = MsgReceivePlus(canalCtrlMsgIn->chid, &canMsgRx_dem, sizeof(canMsg_dem_t), &info, NULL);

		if (rcvid == -1)
		{
			slog(SLOG_CRITICAL,"System error. Remove canalCtrlMsgIn");
			name_detach(canalCtrlMsgIn, 0);
			return EXIT_SUCCESS;
		}
		/* si msCan n'a pas retourne d'erreur */
		if (canMsgRx_dem.status == SECUCAN_OK)
		{
			numCan = canMsgRx_dem.numCan;
			nbElem = canMsgRx_dem.nbElem;

			while(nbElem)
			{
				cobId  = canMsgRx_dem.canMsg[nbElem-1].trame.cob_id;
				nodeId = canMsgRx_dem.canMsg[nbElem-1].trame.cob_id & 0x7F;
				/* suppression de la plage > 0x3F, utilisee par le SDO2 Infranor */
				nodeId = nodeId & (~0x40);
				/*--------------------------------*/
				/* si c'est un variateur Infranor */
				/*--------------------------------*/
				if ((secuAdm.typeNode[numCan][nodeId-1] & TYP_NOD_CAN) == ID_NOD_CAN_VAR &&
					(secuAdm.typeNode[numCan][nodeId-1] & TYP_VAR_CAN) == ID_INFRANOR)
				{
					pthread_mutex_lock(&secuAdm.mutexSecu);

					/* reception du status word via un PDO */
					if ((cobId & (0x780|0x40)) == 0x180)
					{
						inSecu.statusWord[numCan][nodeId-1]  = canMsgRx_dem.canMsg[nbElem-1].trame.data[0] & 0x00FF;
						inSecu.statusWord[numCan][nodeId-1] |= canMsgRx_dem.canMsg[nbElem-1].trame.data[1] << 8;
					}
					/* reception du status word via un SDO */
					else if ((cobId & (0x780|0x40)) == 0x580)
					{
						inSecu.statusWord[numCan][nodeId-1]  = canMsgRx_dem.canMsg[nbElem-1].trame.data[4] & 0x00FF;
						inSecu.statusWord[numCan][nodeId-1] |= canMsgRx_dem.canMsg[nbElem-1].trame.data[5] << 8;
					}
					/* reception des SDO2 des P3G3 */
					else if ((cobId & (0x780|0x40)) == 0x5C0)
					{
						objet  = canMsgRx_dem.canMsg[nbElem-1].trame.data[1] & 0x00FF;
						objet |= canMsgRx_dem.canMsg[nbElem-1].trame.data[2] << 8;
						if (objet == 0x3001){
							/* lecture des entrees STO */
							stoInput  = canMsgRx_dem.canMsg[nbElem-1].trame.data[4] & 0x00FF;
							stoInput |= canMsgRx_dem.canMsg[nbElem-1].trame.data[5] << 8;
							if (stoInput == 0) {
								inSecu.stoInput[numCan] |= 1 << (nodeId-1);
								slog(SLOG_DEBUG1,"stoInput[%d] = 0x%04X, node = %d", numCan, inSecu.stoInput[numCan], nodeId);
							}
							else {
								inSecu.stoInput[numCan] &= ~(1 << (nodeId-1));
								slog(SLOG_DEBUG1,"stoInput[%d] = 0x%04X, node = %d", numCan, inSecu.stoInput[numCan], nodeId);
							}
							inSecu.objetStoValide[numCan] |= 1 << (nodeId-1);
						}
						else if (objet == 0x3020){
							/* lecture des codes d'erreur pour determiner si la puissance */
							/* du variateur est coupee lors d'un arret de securite        */
							/* Le controle des entrees STO est masque si c'est le cas     */
							emerCode  = canMsgRx_dem.canMsg[nbElem-1].trame.data[4];
							emerCode |= canMsgRx_dem.canMsg[nbElem-1].trame.data[5] << 8;
							emerCode |= canMsgRx_dem.canMsg[nbElem-1].trame.data[6] << 16;
							emerCode |= canMsgRx_dem.canMsg[nbElem-1].trame.data[7] << 24;
							if (emerCode & 0x00100000){
								inSecu.puissanceOn[numCan] &= ~(1 << (nodeId-1));
								slog(SLOG_DEBUG1,"puissanceOn[%d] = 0x%08X, error code = 0x%08X, node = %d", numCan, inSecu.puissanceOn[numCan], emerCode, nodeId);
							}
							else{
								inSecu.puissanceOn[numCan] |= 1 << (nodeId-1);
								slog(SLOG_DEBUG1,"puissanceOn[%d] = 0x%08X, error code = 0x%08X, node = %d", numCan, inSecu.puissanceOn[numCan], emerCode, nodeId);
							}
						}
					}
					/* reception de la vitesse du moteur */
					else if ((cobId & (0x780|0x40)) == 0x380)
					{
						vit[numCan][nodeId-1]  = canMsgRx_dem.canMsg[nbElem-1].trame.data[4] & 0x000000FF;
						vit[numCan][nodeId-1] |= canMsgRx_dem.canMsg[nbElem-1].trame.data[5] << 8;
						vit[numCan][nodeId-1] |= canMsgRx_dem.canMsg[nbElem-1].trame.data[6] << 16;
						vit[numCan][nodeId-1] |= canMsgRx_dem.canMsg[nbElem-1].trame.data[7] << 24;

						if (outSecu.stopAxes && inSecu.axesArretes == FALSE &&
						   (enMouv[numCan] & (1 << (nodeId-1))) != 0)
						{
							vit_abs = abs(vit[numCan][nodeId-1]);
							vit_abs_old = abs(vit_old[numCan][nodeId-1]);

							if (vit_abs < 10)
							{
								enMouv[numCan] &= ~(1 << (nodeId-1));
								slog(SLOG_DEBUG1,"nodeId %d on bus %d is stopped (enMouv[%d]=0x%08X)", nodeId, numCan, numCan, enMouv[numCan]);

								for(n=0; n<MAX_BUS_NUMBER; n++)
								{
									if (enMouv[n] != 0)
										break;
									if (n == (MAX_BUS_NUMBER - 1))
									{
										slog(SLOG_DEBUG1,"all axis are stopped, switching category 0 stop");
										inSecu.axesArretes = TRUE;
									}
								}
							}
							else if (vit_abs >= vit_abs_old)
							{
								if (enAccel[numCan][nodeId-1] > secuAdm.timeOut_stop[numCan][nodeId-1])
								{
									//slog(SLOG_WARNING,"The nodeId %d speed is too high (be careful the switching category 0 stop is disabled)", nodeId);
									// inSecu.axesArretes = TRUE;
								}
								else
								{
									enAccel[numCan][nodeId-1] ++;
									slog(SLOG_DEBUG1,"the nodeId %d speed is too high (%d/%d)", nodeId, enAccel[numCan][nodeId-1], secuAdm.timeOut_stop[numCan][nodeId-1]);
								}
							}
							else
							{
								vit_old[numCan][nodeId-1] = vit[numCan][nodeId-1];
								if (enAccel[numCan][nodeId-1] > 0)
								{
									enAccel[numCan][nodeId-1] --;
									slog(SLOG_DEBUG1,"the nodeId %d speed is ok (%d/%d)", nodeId, enAccel[numCan][nodeId-1], secuAdm.timeOut_stop[numCan][nodeId-1]);
								}
							}
						}
						else if (!outSecu.stopAxes)
						{
							enAccel[numCan][nodeId-1] = 0;
							enMouv[numCan]  = secuAdm.nodesSecu[numCan];
							enMouv[numCan] &= outSecu.nodesPlugged[numCan];
							vit_old[numCan][nodeId-1] = vit[numCan][nodeId-1];
						}
					}
					/* reception d'un Emergency */
					else if (((cobId & (0x780|0x40)) == 0x80) &&
							((canMsgRx_dem.canMsg[nbElem-1].trame.data[0] != 0) || (canMsgRx_dem.canMsg[nbElem-1].trame.data[1] != 0)) &&
							((outSecu.nodesPlugged[numCan] >> (nodeId - 1)) & 1) == 1)
					{
						/* On recupere les codes d'erreur specifique au fabriquant */
						emerCode  = canMsgRx_dem.canMsg[nbElem-1].trame.data[3];
						emerCode |= canMsgRx_dem.canMsg[nbElem-1].trame.data[4] << 8;
						emerCode |= canMsgRx_dem.canMsg[nbElem-1].trame.data[5] << 16;
						emerCode |= canMsgRx_dem.canMsg[nbElem-1].trame.data[6] << 24;

						/* On ignore les defauts sous tension si la puissance est retombee */
						if (!(outSecu.validAxeInt == 0 && emerCode == 0x00100000))
						{
							inSecu.emerError[numCan] |= 1 << (nodeId-1);
							SET_ERROR(SECU_VAR_ERROR, GEST_EMERGENCY, emerCode);

							/* On impose une demande d'init des axes sur un defaut cable resolver */
							if ((emerCode & 0x00200000) == 0x00200000)
							{
								inSecu.forceInit[numCan] |= 1 << (nodeId-1);
								slog(SLOG_WARNING,"Resolver fault");
							}
						}
					}
					pthread_mutex_unlock(&secuAdm.mutexSecu);
				}
				/*-----------------------------*/
				/* si c'est un variateur Deimo */
				/*-----------------------------*/
				if ((secuAdm.typeNode[numCan][nodeId-1] & TYP_NOD_CAN) == ID_NOD_CAN_VAR &&
					(secuAdm.typeNode[numCan][nodeId-1] & TYP_VAR_CAN) == ID_DEIMO)
				{
					pthread_mutex_lock(&secuAdm.mutexSecu);

					/* reception d'un Emergency */
					if (((cobId & 0x780) == 0x80) &&
						((canMsgRx_dem.canMsg[nbElem-1].trame.data[0] != 0) ||
						 (canMsgRx_dem.canMsg[nbElem-1].trame.data[1] != 0)))
					{
						/* On recupere les codes d'erreur specifique au fabriquant */
						emerCode  = canMsgRx_dem.canMsg[nbElem-1].trame.data[0];
						emerCode |= canMsgRx_dem.canMsg[nbElem-1].trame.data[1] << 8;

						/* On ignore les defauts sous tension si la puissance est retombee  */
						if (!(outSecu.validAxeInt == 0 && emerCode == 0xFF03))
						{
							inSecu.emerError[numCan] |= 1 << (nodeId-1);
							SET_ERROR(SECU_VAR_ERROR, GEST_EMERGENCY, emerCode);
						}
					}
					pthread_mutex_unlock(&secuAdm.mutexSecu);
				}
				/*------------------------------*/
				/* si c'est une carte Interface */
				/*------------------------------*/
				if (secuAdm.typeNode[numCan][nodeId-1] == ID_NOD_CAN_INTERFACE)
				{
					pthread_mutex_lock(&secuAdm.mutexSecu);

					/* reception des sorties de la carte Interface */
					if ((cobId & 0x780) == 0x180)
					{
						numInt = secuAdm.numInt[numCan][nodeId-1];

						if (canMsgRx_dem.canMsg[nbElem-1].trame.data[0] & READY_INT)
							inSecu.readyInt |=  (1 << numInt);
						else
							inSecu.readyInt &= ~(1 << numInt);

						if (canMsgRx_dem.canMsg[nbElem-1].trame.data[0] & ERROR_INT)
							inSecu.errorInt |=  (1 << numInt);
						else
							inSecu.errorInt &= ~(1 << numInt);

						if (canMsgRx_dem.canMsg[nbElem-1].trame.data[0] & VALIDAXE_INT)
							inSecu.validAxeInt |=  (1 << numInt);
						else
							inSecu.validAxeInt &= ~(1 << numInt);

						if (canMsgRx_dem.canMsg[nbElem-1].trame.data[0] & POWER_OK_INT)
							inSecu.powerOkInt |=  (1 << numInt);
						else
							inSecu.powerOkInt &= ~(1 << numInt);

						if (canMsgRx_dem.canMsg[nbElem-1].trame.data[0] & VAGV_INT)
							inSecu.vagvInt |=  (1 << numInt);
						else
							inSecu.vagvInt &= ~(1 << numInt);

						if (canMsgRx_dem.canMsg[nbElem-1].trame.data[0] & PROTECT_OK_INT)
							inSecu.protectOkInt |=  (1 << numInt);
						else
							inSecu.protectOkInt &= ~(1 << numInt);

						/* prise en compte des etats ready et error des cartes Interface */
						if (inSecu.errorInt)
							SET_ERROR(SECU_INT_ERROR, SECU_INTERFACE, 0);
					}
					/* reception d'un Emergency */
					if (((cobId & 0x780) == 0x80) &&
						((canMsgRx_dem.canMsg[nbElem-1].trame.data[0] != 0) ||
						 (canMsgRx_dem.canMsg[nbElem-1].trame.data[1] != 0)))
					{
						/* On recupere le code d'erreur specifique au fabriquant */
						emerCode  = canMsgRx_dem.canMsg[nbElem-1].trame.data[3];
						emerCode |= canMsgRx_dem.canMsg[nbElem-1].trame.data[4] << 8;
						emerCode |= canMsgRx_dem.canMsg[nbElem-1].trame.data[5] << 16;
						emerCode |= canMsgRx_dem.canMsg[nbElem-1].trame.data[6] << 24;

						inSecu.emerError[numCan] |= 1 << (nodeId-1);
						SET_ERROR(SECU_INT_ERROR, GEST_EMERGENCY, emerCode);
					}
					pthread_mutex_unlock(&secuAdm.mutexSecu);
				}
				nbElem--;
			}
		}
		else
		{
			slog(SLOG_ERROR,"Reception error. The CAN driver generated an error during a reception");
		}
		/* Reponse a secuCan */
		MsgReply(rcvid, 0, NULL, NULL);
	}
}

/**
 * \brief Communication avec le serveur VNC
 * 		  Les evennements emis par VNC-server sont relayes vers dec_vnc si le pendant
 *        est sur son support et que le mode inhibition des protecteurs est inactif.
 *        Dans le cas contraire, les evennements sont bloques.
 * \param
 * \return
 */
void *thread_vncServer (void *coidDevVnc)
{
	name_attach_t *canal_vncServer;
	int rcvid;
	msg_pointer_t msg_vnc;
	uint32_t resp_vnc;
	struct _msg_info info;
	int ret;
	int vnc_permis;

	pthread_setname_np(pthread_self(),"thread_vncServer");

	/* Point de connexion pour VNC server */
	slog(SLOG_INFO,"Channels creation for VNC server");
	canal_vncServer = name_attach(NULL, DEVI_VNC_MSG_SECU, NAME_FLAG_ATTACH_GLOBAL);
	if (canal_vncServer == NULL){
		slog(SLOG_SHUTDOWN,"System error. Impossible to create the canal devi-vnc-secu");
		return EXIT_SUCCESS;
	}
	while (1){
		/* attente du message a relayer */
		rcvid = MsgReceivePlus(canal_vncServer->chid, &msg_vnc, sizeof(msg_pointer_t), &info, NULL);
		if (rcvid == -1){
			slog(SLOG_CRITICAL,"System error. MsgReceivePulse() function produced an error");
			delay(1000);
			continue;
		}
		/* envoi du message a dev_vnc si secu l'autorise */
		pthread_mutex_lock(&secuAdm.mutexSecu);
		if (outSecu.modeVnc != display_mode_local_verrou){
			vnc_permis = 1;
		}
		else{
			vnc_permis = 0;
			resp_vnc = ERROR;
		}
		pthread_mutex_unlock(&secuAdm.mutexSecu);
		if (vnc_unsafe_mode)
			vnc_permis = 1;
		if (vnc_permis){
			ret = MsgSendPlus((int)coidDevVnc, &msg_vnc, sizeof(msg_pointer_t), &resp_vnc, sizeof(resp_vnc), 500);
			if (ret < 0){
				resp_vnc = ERROR;
			}
		}
		/* reponse au serveur vnc */
		MsgReply(rcvid, 0, &resp_vnc, sizeof(resp_vnc));
	}
}

static void thread_vncDisplay_cleanup(void *arg)
{
	name_attach_t *attach = (name_attach_t *)arg;
	if (arg != NULL)
		name_detach(attach, 0);
}

/**
 * \brief Communication avec VNC display
 * 		  VNC display emet des demandes pour activer l'IHM sur le pendant ou sur le pupitre
 *        de la presse. L'ecran actif est ensuite valide par le thread principal
 *
 * \param
 * \return
 */
void *thread_vncDisplay (void *arg)
{
	void *cp_arg = arg;
	cp_arg = NULL;
	name_attach_t *canal_vncDisplay = NULL;
	int rcvid;
	secu_vnc_msg_t msg;
	struct _msg_info info;
	secu_vnc_t dem_mode = secu_vnc_dem_local;
	int erreur = 0;

	pthread_setname_np(pthread_self(),"thread_vncServer");
	pthread_cleanup_push(thread_vncDisplay_cleanup, canal_vncDisplay);
	/* Point de connexion pour VNC server */
	SEPROLOGD(M_SECU, SLOG_INFO,"Channels creation for VNC server");
	canal_vncDisplay = name_attach(NULL, SECU_VNC, NAME_FLAG_ATTACH_GLOBAL);
	if (canal_vncDisplay == NULL){
		slog(SLOG_SHUTDOWN,"System error. Impossible to create the canal secu_vnc");
		goto out;
	}
	do {
		/* Attente d'une nouvelle demande de permutation des ecrans */
		rcvid = MsgReceivePlus(canal_vncDisplay->chid, &msg, sizeof(msg), &info, NULL);
		if (rcvid < 0){
			slog(SLOG_CRITICAL,"System error. MsgReceivePulse_r() returned %d", rcvid);
			dem_mode = secu_vnc_dem_local;
			erreur = 1;
			delay(100);
		}
		switch (msg.mode) {
		case secu_vnc_dem_local:
		case secu_vnc_dem_oem:
			dem_mode = msg.mode;
			MsgReply(rcvid, EOK, 0, 0);
			break;
		case secu_vnc_unsafe:
			slog(SLOG_WARNING, "Test mode enabled");
			vnc_unsafe_mode = 1;
			MsgReply(rcvid, EOK, 0, 0);
			break;
		default:
			slog(SLOG_ERROR,"System error. dem_mode = %d from %d", msg.mode, info.pid);
			dem_mode = secu_vnc_dem_local;
			MsgError(rcvid, EINVAL);
			delay(100);
			break;
		}
		pthread_mutex_lock(&secuAdm.mutexSecu);
		inSecu.demModeVnc = dem_mode;
		pthread_mutex_unlock(&secuAdm.mutexSecu);
	} while (!erreur);

	out:
	pthread_cleanup_pop(1);
	return NULL;
}

/*=========================================================
  Function Name  : configFiltre
  Description    : Fonction de configuration des filtres can
  Parameter      : pointeur sur la strucure locale
  Return         : 0 ou erreur
=========================================================*/
int configFiltre(secuLoc_t *pSecu)
{
	int result = 0;
	canFilter_t canFilter[MAX_BUS_NUMBER];
	unsigned short *idx;
	table_t *table;
	int i;
	int numCan;
	int nodes;
	int numNode;

	/* Reset des buffers */
	for(numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
	{
		memset(&canFilter[numCan].filterTx, 0, sizeof(filter_t));
	}
	/*================================*/
	/* Filtrage des messages entrants */
	/*================================*/

	/* Recherche des composants de secu */
	for(numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
	{
		idx    = &canFilter[numCan].filterRx.index[0];
		table  = &canFilter[numCan].filterRx.table[0];
		i      = 1;
		nodes  = secuAdm.nodesSecu[numCan];
		nodes &= pSecu->nodesPlugged[numCan];

		while (nodes)
		{
			CNTLZW(numNode, nodes);
			if (numNode == -1)
				break;

			/*--------------------------------*/
			/* si c'est un variateur Infranor */
			/*--------------------------------*/
			if ((secuAdm.typeNode[numCan][numNode] & TYP_NOD_CAN) == ID_NOD_CAN_VAR &&
				(secuAdm.typeNode[numCan][numNode] & TYP_VAR_CAN) == ID_INFRANOR)
			{
				/* recuperation des status word via un PDO */
				table[i].cob_id        = 0x180 + numNode + 1;
				table[i].typeTest      = SANS;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].val.int32.min = 0;
				table[i].val.int32.max = 0;
				table[i].mask[0]       = 0;

				idx[table[i].cob_id] = i;
				i++;

				/* recuperation des status word via un SDO */
				table[i].cob_id        = 0x580 + numNode + 1;
				table[i].typeTest      = EGAL_CODE_AND_MASK;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].mask[0]       = 0xF0;
				table[i].mask[1]       = 0xFF;
				table[i].mask[2]       = 0xFF;
				table[i].mask[3]       = 0xFF;
				table[i].mask[4]       = 0;
				table[i].mask[5]       = 0;
				table[i].mask[6]       = 0;
				table[i].mask[7]       = 0;
				table[i].val.code[0]   = 0x40; // Initiate upload response
				table[i].val.code[1]   = 0x41; // Objet index 0x6041
				table[i].val.code[2]   = 0x60; //
				table[i].val.code[3]   = 0x00; // Sous index 0x00
				table[i].val.code[4]   = 0;
				table[i].val.code[5]   = 0;
				table[i].val.code[6]   = 0;
				table[i].val.code[7]   = 0;

				idx[table[i].cob_id] = i;
				i++;

				/* recuperation des SDO2 du P3G3 (lecture des status STO + error code) */
				table[i].cob_id        = 0x5C0 + numNode + 1;
				table[i].typeTest      = EGAL_CODE_AND_MASK;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].mask[0]       = 0xF0;
				table[i].mask[1]       = 0;
				table[i].mask[2]       = 0;
				table[i].mask[3]       = 0;
				table[i].mask[4]       = 0;
				table[i].mask[5]       = 0;
				table[i].mask[6]       = 0;
				table[i].mask[7]       = 0;
				table[i].val.code[0]   = 0x40; // Initiate upload response
				table[i].val.code[1]   = 0;
				table[i].val.code[2]   = 0;
				table[i].val.code[3]   = 0;
				table[i].val.code[4]   = 0;
				table[i].val.code[5]   = 0;
				table[i].val.code[6]   = 0;
				table[i].val.code[7]   = 0;

				idx[table[i].cob_id] = i;
				i++;

				/* recuperation de la vitesse moteur */
				table[i].cob_id        = 0x380 + numNode + 1;
				table[i].typeTest      = SANS;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].val.int32.min = 0;
				table[i].val.int32.max = 0;
				table[i].mask[0]       = 0;

				idx[table[i].cob_id] = i;
				i++;
			}
			/*-----------------------------*/
			/* si c'est un variateur Deimo */
			/*-----------------------------*/
			if ((secuAdm.typeNode[numCan][numNode] & TYP_NOD_CAN) == ID_NOD_CAN_VAR &&
				(secuAdm.typeNode[numCan][numNode] & TYP_VAR_CAN) == ID_DEIMO)
			{
				/* recuperation des status word et de la vitesse via un PDO */
				table[i].cob_id        = 0x180 + numNode + 1;
				table[i].typeTest      = SANS;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].val.int32.min = 0;
				table[i].val.int32.max = 0;
				table[i].mask[0]       = 0;

				idx[table[i].cob_id] = i;
				i++;

				/* recuperation des status word via un SDO */
				table[i].cob_id        = 0x580 + numNode + 1;
				table[i].typeTest      = EGAL_CODE_AND_MASK;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].mask[0]       = 0xF0;
				table[i].mask[1]       = 0xFF;
				table[i].mask[2]       = 0xFF;
				table[i].mask[3]       = 0xFF;
				table[i].mask[4]       = 0;
				table[i].mask[5]       = 0;
				table[i].mask[6]       = 0;
				table[i].mask[7]       = 0;
				table[i].val.code[0]   = 0x40; // Initiate upload response
				table[i].val.code[1]   = 0x41; // Objet index 0x6041
				table[i].val.code[2]   = 0x60; //
				table[i].val.code[3]   = 0x00; // Sous index 0x00
				table[i].val.code[4]   = 0;
				table[i].val.code[5]   = 0;
				table[i].val.code[6]   = 0;
				table[i].val.code[7]   = 0;

				idx[table[i].cob_id] = i;
				i++;
			}
			/*------------------------------*/
			/* si c'est une carte Interface */
			/*------------------------------*/
			if (secuAdm.typeNode[numCan][numNode] == ID_NOD_CAN_INTERFACE)
			{
				/* recuperation des sorties de l'interface */
				table[i].cob_id        = 0x180 + numNode + 1;
				table[i].typeTest      = SANS;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].val.int32.min = 0;
				table[i].val.int32.max = 0;
				table[i].mask[0]       = 0;

				idx[table[i].cob_id] = i;
				i++;
			}
			/*----------------------------*/
			/* recuperation des emergency */
			/*----------------------------*/
			table[i].cob_id        = 0x80 + numNode + 1;
			table[i].typeTest      = SANS;
			table[i].byteLow       = 0;
			table[i].len           = 0;
			table[i].val.int32.min = 0;
			table[i].val.int32.max = 0;
			table[i].mask[0]       = 0;

			idx[table[i].cob_id] = i;
			i++;

			nodes &= ~(1 << numNode);
		}
	}
	/*================================*/
	/* Filtrage des messages sortants */
	/*================================*/

	/*----------------------------------*/
	/* Recherche des composants de secu */
	/*----------------------------------*/
	for(numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
	{
		idx   = &canFilter[numCan].filterTx.index[0];
		table = &canFilter[numCan].filterTx.table[0];
		i     = 1;

		nodes  = secuAdm.nodesSecu[numCan];
		nodes &= pSecu->nodesPlugged[numCan];

		while (nodes)
		{
			CNTLZW(numNode, nodes);
			if (numNode == -1)
				break;

			/*--------------------------------*/
			/* si c'est un variateur Infranor */
			/*--------------------------------*/
			if ((secuAdm.typeNode[numCan][numNode] & TYP_NOD_CAN) == ID_NOD_CAN_VAR &&
				(secuAdm.typeNode[numCan][numNode] & TYP_VAR_CAN) == ID_INFRANOR)
			{
				/* pour que secu valide les controls word via le RPDO1 */
				table[i].cob_id        = 0x200 + numNode + 1;
				table[i].typeTest      = SANS;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].val.int32.min = 0;
				table[i].val.int32.max = 0;

				idx[table[i].cob_id] = i;
				i++;

				/* pour que secu valide les controls word via le RPDO1 */
				table[i].cob_id        = 0x300 + numNode + 1;
				table[i].typeTest      = SANS;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].val.int32.min = 0;
				table[i].val.int32.max = 0;

				idx[table[i].cob_id] = i;
				i++;

				/* pour que secu valide les controls word via un SDO*/
				table[i].cob_id        = 0x600 + numNode + 1;
				table[i].typeTest      = EGAL_CODE_AND_MASK;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].mask[0]       = 0xF0;
				table[i].mask[1]       = 0xFF;
				table[i].mask[2]       = 0xFF;
				table[i].mask[3]       = 0xFF;
				table[i].mask[4]       = 0;
				table[i].mask[5]       = 0;
				table[i].mask[6]       = 0;
				table[i].mask[7]       = 0;
				table[i].val.code[0]   = 0x20; // Initiate download request
				table[i].val.code[1]   = 0x40; // Objet index 0x6040
				table[i].val.code[2]   = 0x60; //
				table[i].val.code[3]   = 0x00; // Sous index 0x00
				table[i].val.code[4]   = 0;
				table[i].val.code[5]   = 0;
				table[i].val.code[6]   = 0;
				table[i].val.code[7]   = 0;

				idx[table[i].cob_id] = i;
				i++;
			}
			/*-----------------------------*/
			/* si c'est un variateur Deimo */
			/*-----------------------------*/
			if ((secuAdm.typeNode[numCan][numNode] & TYP_NOD_CAN) == ID_NOD_CAN_VAR &&
				(secuAdm.typeNode[numCan][numNode] & TYP_VAR_CAN) == ID_DEIMO)
			{
				/* pour que secu valide les controls word via le RPDO1 */
				table[i].cob_id        = 0x200 + numNode + 1;
				table[i].typeTest      = SANS;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].val.int32.min = 0;
				table[i].val.int32.max = 0;

				idx[table[i].cob_id] = i;
				i++;

				/* pour que secu valide les controls word via un SDO*/
				table[i].cob_id        = 0x600 + numNode + 1;
				table[i].typeTest      = EGAL_CODE_AND_MASK;
				table[i].byteLow       = 0;
				table[i].len           = 0;
				table[i].mask[0]       = 0xF0;
				table[i].mask[1]       = 0xFF;
				table[i].mask[2]       = 0xFF;
				table[i].mask[3]       = 0xFF;
				table[i].mask[4]       = 0;
				table[i].mask[5]       = 0;
				table[i].mask[6]       = 0;
				table[i].mask[7]       = 0;
				table[i].val.code[0]   = 0x20; // Initiate download request
				table[i].val.code[1]   = 0x40; // Objet index 0x6040
				table[i].val.code[2]   = 0x60; //
				table[i].val.code[3]   = 0x00; // Sous index 0x00
				table[i].val.code[4]   = 0;
				table[i].val.code[5]   = 0;
				table[i].val.code[6]   = 0;
				table[i].val.code[7]   = 0;

				idx[table[i].cob_id] = i;
				i++;
			}
			nodes &= ~(1 << numNode);
		}
	}
	/*-----------------------------*/
	/* Envoi des filtres a secuCan */
	/*-----------------------------*/
	for(numCan=0; numCan<MAX_BUS_NUMBER && !result; numCan++)
	{
		if (secuAdm.nodesSecu[numCan])
		{
			result = MsgSendPlus(pSecu->coidMajFiltreCan[numCan], &canFilter[numCan], sizeof(canFilter), NULL, 0, TIMEOUT_CONF_FILTER);

			if (result == -ETIMEDOUT)
			{
				slog(SLOG_ERROR,"SecuCan %d communication error (%s)", numCan, strerror(-result));
				SET_ERROR(SECUCAN_ERROR, 0, 0);
			}
			else if (result < 0)
			{
				slog(SLOG_CRITICAL,"SecuCan %d communication error (%s)", numCan, strerror(-result));
				SET_ERROR(QNX_ERROR, 0, 0);
			}
		}
	}
	return (result);
}

/*=========================================================
  Function Name  : init
  Description    : Initialisation de la librairie
  Parameter      : None
  Return         : None
=========================================================*/
int initSecu(secuLoc_t *pSecu)
{
	int result;
	int status;
	unsigned long long typesDonnees;
	int typeNode;
	int numCan;
	int node;
	int nbreIntDetectee;
	char canal[30];
	statusSrvDonnee_e statusSrvParam;
	statusSrvDonnee_t statusSrvDonnee;
	srvDonneeConnect_t *connection;
	int typeTrans;
	int sync_period;

	result          = 0;
	status          = OK;
	nbreIntDetectee = 0;
	connection = &pSecu->connectServDonnees;

	/*-----------------------------------------------------*/
	/* Demarrage threads de controle des messages sortants */
	/*-----------------------------------------------------*/
	if (simu == FALSE)
	{
		if(demarrer_thread(NULL, thread_ctrlMsgOut, NULL, getprio(getpid()), 8) < 0 )
		{
			slog(SLOG_CRITICAL,"System error. Impossible to create the thread <thread_ctrlMsgOut>");
			return (QNX_ERROR);
		}
	}
	/*-----------------------------------------------------*/
	/* Demarrage threads de controle des messages entrants */
	/*-----------------------------------------------------*/
	if (simu == FALSE)
	{
		if(demarrer_thread(NULL, thread_ctrlMsgIn, NULL, getprio(getpid()), 8) < 0 )
		{
			slog(SLOG_CRITICAL,"System error. Impossible to create the thread <thread_ctrlMsgIn>");
			return (QNX_ERROR);
		}
	}
	/*--------------------------*/
	/* Initialisation des mutex */
	/*--------------------------*/
	result  = pthread_mutex_init(&secuAdm.mutexSecu,  NULL);
	result |= pthread_mutex_init(&secuAdm.mutexStatus,NULL);

	if (result != EOK)
	{
		slog(SLOG_CRITICAL,"System error. An error occurred during initialization of a mutex");
		return (QNX_ERROR);
	}
	/*-------------------------------*/
	/* Initialisation des semaphores */
	/*-------------------------------*/
	result  = sem_init(&secuAdm.semThreadExec,0,0);
	result |= sem_init(&secuAdm.semThreadManu,0,0);
	result |= sem_init(&secuAdm.semThreadSpi,0,0);
	result |= sem_init(&secuAdm.semCtrlAxes,0,0);
	result |= sem_init(&secuAdm.semComSpi,0,0);
	result |= sem_init(&secuAdm.semStaubli,0,0);

	if (result)
	{
		slog(SLOG_CRITICAL,"System error. An error occurred during initialization of a semaphore");
		return (QNX_ERROR);
	}
	/*----------------------------------------------------------------*/
	/* Synchro avec le serveur de donnees et le serveur de parametres */
	/*----------------------------------------------------------------*/
	syncdem_etape(M_SECU);

	/*--------------------------------------*/
	/* Connexion avec le serveur de donnees */
	/*--------------------------------------*/
	for(typesDonnees=debutTypeDonnee+1; typesDonnees<finTypeDonnee; typesDonnees++)
	{
		ptTableau[typesDonnees] = NULL;
	}
	ptTableau[wrdSysteme] = &tul_Word[DEBUT_WRD_SYSTEME];
	ptTableau[wrdStep]    = &tul_Word[DEBUT_WRD_STEP];
	ptTableau[wrdSysteme1] = &tul_Word[DEBUT_WRD_SYSTEME1];

	statusSrvDonnee = SrvDonnee_init(MOD_SECU,&pSecu->connectServDonnees,ptTableau);

	if (statusSrvDonnee.status != pasErreur)
	{
		slog(SLOG_CRITICAL,"Data server connection error");
		return (QNX_ERROR);
	}
	/*-------------------------------------------------*/
	/* Lecture des options commerciales dans InfoRobot */
	/*-------------------------------------------------*/
	statusSrvDonnee = SrvDonnee_lect(&pSecu->connectServDonnees, MSG_TYPE(wrdSysteme) | MSG_TYPE(wrdSysteme1), 0);

	if (statusSrvDonnee.status != pasErreur)
	{
		slog(SLOG_CRITICAL,"System error. The Data Server generated an error during a reading. srvStatus is %d", (int)statusSrvDonnee.status);
		return (QNX_ERROR);
	}
	wordsToOptCom(pTAB_OFFSET(wrdSysteme, OPTIONS_COMMERCIALES1),
				  pTAB_OFFSET(wrdSysteme, OPTIONS_COMMERCIALES2),
				  pTAB_OFFSET(wrdSysteme1, OPTIONS_COMMERCIALES3),
				  &secuAdm.options);

	/*-----------------------------------------*/
	/* Connexion avec le serveur de parametres */
	/*-----------------------------------------*/
	result = sem_init(&secuAdm.synchroParam,0,1);

	if (result)
	{
		slog(SLOG_CRITICAL,"System error. An error occurred during initialization of a semaphore");
		return (QNX_ERROR);
	}
	slog(SLOG_DEBUG1,"Connection with Parameters Server");

	if ((statusSrvParam = SrvParam_init(&majParam)) != pasErreur)
	{
		slog(SLOG_CRITICAL,"System error. An error occurred during initialization of connection with Parameters Server");
		return (QNX_ERROR);
	}

	// bloque les paramètres le temps de l'init !!!
	sem_wait(&secuAdm.synchroParam);

	/*---------------------------------------------------------*/
	/* Initialisation des variables dependantes des parametres */
	/*---------------------------------------------------------*/
	/* recherche des variateurs et de la carte Interface */
	for (numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
	{
		for (node=0; node<MAX_NOD_CAN; node++)
		{
			typeNode = getParam(secuAdm.bdp, G_CAN1+numCan, F_NODE1+node, I_TYPE_CAN);
			if ((typeNode & TYP_NOD_CAN) == ID_NOD_CAN_VAR)
			{
				secuAdm.typeNode[numCan][node]   = typeNode;
				secuAdm.nodesSecu[numCan]       |= (1 << node);
				secuAdm.axePresent				 = 1;
				inSecu.puissanceOn[numCan]		|= (1 << node);

				inSecu.controlWord[numCan][node] &= ~CTRL_WORD_NOT_QUICKSTOP; /* pour forcer le QuickStop */
				inSecu.controlWord[numCan][node] &= ~CTRL_WORD_VAGV;          /* pour forcer le VAGV a 0  */
				inSecu.controlWord[numCan][node] |= CTRL_WORD_OUT_OF_LIMIT;

				inSecu.statusWord[numCan][node] |= STATUS_WORD_NOT_QUICKSTOP; /* pour forcer l'envoi du QuickStop */
				inSecu.statusWord[numCan][node] &= ~STATUS_WORD_NOT_VAGV;     /* pour forcer l'envoi du VAGV a 0  */

				/* time out (en nbre de synchro) sur le controle des arrets de securite */
				sync_period = getParam(secuAdm.bdp, G_CAN1+numCan, F_MSTR, I_MSTR_PERIOD_SYNC);
				if (sync_period == 0)
					sync_period = 1;
				secuAdm.timeOut_stop[numCan][node] = 60 / sync_period;
				typeTrans = getParam(secuAdm.bdp, G_CAN1+numCan, F_NODE1+node, I_CLASS);
				if (typeTrans > 1 && typeTrans <= 240)
					secuAdm.timeOut_stop[numCan][node] /= typeTrans;
			}
			else if(typeNode == ID_NOD_CAN_INTERFACE)
			{
				nbreIntDetectee++;
				if (nbreIntDetectee > MAX_INT_NUMBER)
				{
					slog(SLOG_WARNING,"Safety error. Secu detected too many Interface board");
					continue;
				}
				secuAdm.busInterface[nbreIntDetectee-1]  = numCan;
				secuAdm.nodeInterface[nbreIntDetectee-1] = node + 1;
				secuAdm.typeNode[numCan][node]           = typeNode;
				secuAdm.nodesSecu[numCan]               |= (1 << node);
				secuAdm.nodesSupportHb[numCan]          |= (1 << node);
				secuAdm.numInt[numCan][node]             = nbreIntDetectee - 1;
			}
		}
	}
	while (nbreIntDetectee < 32)
	{
		inSecu.validAxeInt  |= 1 << nbreIntDetectee;  /* Les bits non utilises sont forcese1 */
		inSecu.powerOkInt   |= 1 << nbreIntDetectee;  /* Les bits non utilises sont forcese1 */
		inSecu.vagvInt      |= 1 << nbreIntDetectee;  /* Les bits non utilises sont forcese1 */
		inSecu.protectOkInt |= 1 << nbreIntDetectee;  /* Les bits non utilises sont forcese1 */
		inSecu.readyInt     |= 1 << nbreIntDetectee;  /* Les bits non utilises sont forcese1 */
		nbreIntDetectee++;
	}
	inSecu.axesPlugged     = 0xFFFFFFFF;           /* Tous les axes sont connectes par defaut   */
	inSecu.nodesPlugged[0] = 0xFFFFFFFF;           /* Tous les noeuds sont connectes par defaut */
	inSecu.nodesPlugged[1] = 0xFFFFFFFF;           /* Tous les noeuds sont connectes par defaut */
	inSecu.sansPendant     = TRUE;                 /* On demarre sans pendant                   */
	inSecu.bauIhm          = TRUE;                 /* Pour eviter un defaut IHM au demarrage    */

	inSecu.demModeVnc      = -1;

	/*-------------------------------------*/
	/* Connexion avec la librairie secuCan */
	/*-------------------------------------*/
	if (simu == FALSE)
	{
		for(numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
		{
			if (secuAdm.nodesSecu[numCan])
			{
				if (numCan == 0)
					sprintf(canal, CANAL_MAJ_FILTRE_CAN_0);
				else
					sprintf(canal, CANAL_MAJ_FILTRE_CAN_1);

				slog(SLOG_DEBUG1,"Connection with SecuCan_%d", numCan);

				if ((pSecu->coidMajFiltreCan[numCan] = name_open(canal, 0)) == -1)
				{
					slog(SLOG_CRITICAL,"secuCan %d module connection error", numCan);
					return (QNX_ERROR);
				}
			}
		}
	}
	/*---------------------------------*/
	/* Connexion avec les driver msCan */
	/*---------------------------------*/
	if (simu == FALSE)
	{
		for(numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
		{
			if (secuAdm.nodesSecu[numCan])
			{
				sprintf(canal, "mscan%d", numCan);
				if ((pSecu->coidMsCan[numCan] = name_open(canal, 0)) == -1)
				{
					slog(SLOG_CRITICAL,"msCan driver %d connection error", numCan);
					return (QNX_ERROR);
				}
			}
		}
	}
	/*---------------------------------------------------*/
	/* Attente demarrage des modules Axe, Exec et Manuel */
	/*---------------------------------------------------*/
	syncdem_etape(M_SECU);

	/*-------------------------------------------------------------*/
	/* Connexion avec le Module Axe si au moins un axe est present */
	/*-------------------------------------------------------------*/
	if (secuAdm.axePresent != 0)
	{
		slog(SLOG_DEBUG1,"Connection with AXES module");

		if ((pSecu->coidModuleAxe = name_open(MODULE_AXES, 0)) == -1)
		{
			slog(SLOG_CRITICAL,"AXES module connection error");
			return (QNX_ERROR);
		}
	}
	/*------------------------*/
	/* Connexion avec dev_vnc */
	/*------------------------*/
	slog(SLOG_DEBUG1, "Connection with devi-vnc");
	if ((pSecu->coidDevVnc = name_open(DEVI_VNC_MSG, NAME_FLAG_ATTACH_GLOBAL)) == -1)
	{
		slog(SLOG_CRITICAL,"devi-vnc connection error");
		return (QNX_ERROR);
	}
	/*----------------------------*/
	/* Connexion avec VNC display */
	/*----------------------------*/
	slog(SLOG_DEBUG1, "Connection with vnc_display");
	if ((pSecu->coidVncDisplay = name_open(VNC_DISPLAY_COMMANDE, NAME_FLAG_ATTACH_GLOBAL)) == -1)
	{
		slog(SLOG_CRITICAL,"vnc_display connection error");
		return (QNX_ERROR);
	}
	/*----------------------------*/
	/* Connexion avec IHM display */
	/*----------------------------*/
	slog(SLOG_DEBUG1, "Connection with ihm_display");
	if ((pSecu->coidIhmDisplay = name_open(IHM_DISPLAY_COMMANDE, NAME_FLAG_ATTACH_GLOBAL)) == -1)
	{
		slog(SLOG_CRITICAL,"ihm_display connection error");
		return (QNX_ERROR);
	}
	/*--------------------------------*/
	/* demarrage du thread auxiliaire */
	/*--------------------------------*/
	if(demarrer_thread(NULL, thread_comm_vncDisplay, pSecu, getprio(getpid()), 32) < 0 )
	{
		slog(SLOG_CRITICAL,"System error. Impossible to create the thread <thread_comm_vncDisplay>");
		return (QNX_ERROR);
	}
	/*---------------------------------------------*/
	/* Threads de communication avec le driver SPI */
	/*---------------------------------------------*/
	if(demarrer_thread(NULL, thread_spi, NULL, getprio(getpid()), 8) < 0 )
	{
		slog(SLOG_CRITICAL,"System error. Impossible to create the thread <thread_driverSpi>");
		return (QNX_ERROR);
	}
	/*------------------------------------*/
	/* Threads de controle du module Exec */
	/*------------------------------------*/
	if(demarrer_thread(NULL, thread_ctrlExec, NULL, getprio(getpid()), 8) < 0 )
	{
		slog(SLOG_CRITICAL,"System error. Impossible to create the thread <thread_ctrlExec>");
		return (QNX_ERROR);
	}
	/*--------------------------------------*/
	/* Threads de controle du module Manuel */
	/*--------------------------------------*/
	if(demarrer_thread(NULL, thread_ctrlManuel, NULL, getprio(getpid()), 8) < 0 )
	{
		slog(SLOG_CRITICAL,"System error. Impossible to create the thread <thread_ctrlManuel>");
		return (QNX_ERROR);
	}
	/*-----------------------------------------------------*/
	/* Threads de communication avec le serveur de donnees */
	/*-----------------------------------------------------*/
	if(demarrer_thread(NULL, thread_servDonnees, NULL, getprio(getpid()), 8) < 0 )
	{
		slog(SLOG_CRITICAL,"System error. Impossible to create the thread <thread_servDonnees>");
		return (QNX_ERROR);
	}
	/*---------------------------------------*/
	/* Threads de communication avec staubli */
	/*---------------------------------------*/
	if (secuAdm.options.Axes.robot6x != sans6x)
	{
		lib6x_setOptionComm(secuAdm.options.Axes.robot6x);
		slog(SLOG_INFO, "Connection with CS8 CNC");
		if (ERROR == lib6x_init(secuAdm.bdp, PORT4_STAUBLI))
		{
			slog(SLOG_CRITICAL,"libStaubliInit has returned an error");
			return (QNX_ERROR);
		}
		slog(SLOG_DEBUG1, "Init Staubli ok");

		if(demarrer_thread(NULL, thread_staubli, NULL, getprio(getpid()), 8) < 0 )
		{
			slog(SLOG_CRITICAL,"System error. Impossible to create the thread <thread_staubli>");
			return (QNX_ERROR);
		}
	}
	/*---------------------------------------------------------*/
	/* Threads de communication avec vnc_server et vnc_display */
	/*---------------------------------------------------------*/
	if(demarrer_thread(NULL, thread_vncServer, (void *)pSecu->coidDevVnc, getprio(getpid()), 8) < 0 )
	{
		slog(SLOG_CRITICAL,"System error. Impossible to create the thread <thread_vncServer>");
		return (QNX_ERROR);
	}
	if(demarrer_thread(NULL, thread_vncDisplay, NULL, getprio(getpid()), 8) < 0 )
	{
		slog(SLOG_CRITICAL,"System error. Impossible to create the thread <thread_vncDisplay>");
		return (QNX_ERROR);
	}
	slog(SLOG_DEBUG1, "Init secu Ok");

	// bloque les paramètres le temps de l'init !!!
	sem_post(&secuAdm.synchroParam);
	return (0);
}

/*============================================================================
  Function Name  : sendMsgCan
  Description    : Fonction generique d'envoi d'un message vers le driver CAN
  Parameter      : La trame a envoyer
                   timeout sur le SendMsg en ms
  Return         : None
=============================================================================*/
int sendMsgCan(canByte_t msg, int numCan, secuLoc_t *pSecu, int time_out)
{
	int result;
	mscanMsg_t msgCan;
	int msgReply;

	struct  sigevent    event;
	event.sigev_notify = SIGEV_UNBLOCK;

	result = 0;

	msgCan.action = WRITE;
	memcpy(&msgCan.msg, &msg, sizeof(canByte_t));
	msgCan.msg.trame.timeStmp = 0;

	result = MsgSendPlus(pSecu->coidMsCan[numCan], &msgCan, sizeof(msgCan), &msgReply, sizeof(msgReply), time_out);

	if (result == -ETIMEDOUT)
	{
		slog(SLOG_ERROR,"mscan %d communication error (%s)", numCan, strerror(-result));
		SET_ERROR(MSCAN_ERROR, 0, 0);
	}
	else if (result < 0)
	{
		slog(SLOG_CRITICAL,"mscan %d communication error (%s)", numCan, strerror(-result));
		SET_ERROR(QNX_ERROR, 0, 0);
	}
	if (msgReply == ERROR)
	{
		slog(SLOG_ERROR,"Transmission error. The CAN driver %d generated an error", numCan);
		SET_ERROR(BUSCAN_ERROR, 0, numCan);
	}
	return (result);
}

/*============================================================================
  Function Name  : convAxeToNode
  Description    : Cette fonction convertit un long ou chaque bit (bit0 = axe0)
                   correspond a un numero d'axe en deux longs ou chaque bit
                   correspond au numero de noeud (bit0 = noeud0)
  Parameter      : Une copie de la variable d'entree
                   Un pointeur sur la variable de sortie
  Return         : None
=============================================================================*/
void convAxeToNode (unsigned long axesPlugged, unsigned long axes, unsigned long *nodes)
{
	long numAxeAss;
	int numAxe;
	int numCan;
	int node;
	int typeVar;
	int numBus;
	int numNode;

	for (numCan=0; numCan<MAX_BUS_NUMBER; numCan++)
	{
		for (node=1; node<=MAX_NOD_CAN; node++)
		{
			/* Recherche l'axe a associer au noeud */
			for (numAxeAss=-1, numAxe=0; numAxe<NOMBRE_VARIATEUR_MAX; numAxe++)
			{
				typeVar = getParam(secuAdm.bdp, G_AXE0+numAxe, F_CONFIG_MATERIEL, I_TYPE_VARIATEUR);
				numBus  = getParam(secuAdm.bdp, G_AXE0+numAxe, F_CONFIG_MATERIEL, I_NUMERO_BUS);
				numNode = getParam(secuAdm.bdp, G_AXE0+numAxe, F_CONFIG_MATERIEL, I_NUMERO_NOEUD_CAN);
				if ((typeVar & TYP_NOD_CAN) != ID_NOD_CAN_VAR || numBus != numCan || node != numNode)
					continue;
				numAxeAss = numAxe;
				if ((axesPlugged >> numAxe) & 1){
					break;
				}	
			}
			/* Conversion */
			if (numAxeAss >= 0 && ((axes >> numAxeAss) & 1) == 1)
			{
				nodes[numCan] |= 1 << (node-1);
			}
			else if (numAxeAss >= 0)
			{
				nodes[numCan] &= ~(1 << (node-1));
			}
		}
	}
}

/*============================================================================
  Function Name  : convNodeToAxe
  Description    : Cette fonction recherche le numero d'axe d'un noeud
  Parameter      : le numero du bus et le numero du noeud
  Return         : le numero de l'axe (-1 si pas trouve)
=============================================================================*/
int convNodeToAxe (unsigned long axesPlugged, int numCan, int numNode)
{
	unsigned long typeVar;
	int numAxe;

	for (numAxe=0; numAxe<NOMBRE_VARIATEUR_MAX; numAxe++)
	{
		typeVar = getParam(secuAdm.bdp, G_AXE0+numAxe, F_CONFIG_MATERIEL, I_TYPE_VARIATEUR);
		if ((typeVar & TYP_NOD_CAN) == ID_NOD_CAN_VAR &&
			(getParam(secuAdm.bdp, G_AXE0+numAxe, F_CONFIG_MATERIEL, I_NUMERO_BUS) == numCan) &&
			(getParam(secuAdm.bdp, G_AXE0+numAxe, F_CONFIG_MATERIEL, I_NUMERO_NOEUD_CAN) == (numNode + 1)) &&
			(axesPlugged & (1 << numAxe)))
			return numAxe;
	}
	return (-1);
}

/*============================================================================
  Function Name  : majParam
  Description    : Cette fonction est appelee a chaque changement des parametres
  Parameter      : Un pointeur sur la base de parametre
  Return         : None
=============================================================================*/
void majParam(PARAMS *bdp)
{
	sem_wait(&secuAdm.synchroParam);
	secuAdm.bdp = bdp;

	/* miseejour des filtres */
	secuAdm.flagMajFilter = 1;

	/*---------------------------------------*/
	/* Reglage de la duree du depart retarde */
	/*---------------------------------------*/
	secuAdm.preStartTime = getParam(secuAdm.bdp, G_SYSTEME, F_EXEC, I_DUREE_DEPART_RETARDE) * 10;   // 1/100s -> 1ms
	if      (secuAdm.preStartTime > 0 && secuAdm.preStartTime < 2000) secuAdm.preStartTime = 2000;
	else if (secuAdm.preStartTime > 5000)                             secuAdm.preStartTime = 5000;

	/*--------------------------------------------*/
	/* Wdog IHM lorsque le pendant est deconnecte */
	/*--------------------------------------------*/
	secuAdm.wdogIhmOffPeriode = getParam(secuAdm.bdp, G_SYSTEME, F_DECONNECT, I_ATTENTE_IHM) * 60000;  // 1mn -> 1ms
	if      (secuAdm.wdogIhmOffPeriode < (5*60000))  secuAdm.wdogIhmOffPeriode = (5*60000);
	else if (secuAdm.wdogIhmOffPeriode > (15*60000)) secuAdm.wdogIhmOffPeriode = (15*60000);

	sem_post(&secuAdm.synchroParam);
}

